const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../config/db');

const ACCESS_COOKIE = process.env.AUTH_ACCESS_COOKIE_NAME || 'vdcms_access';
const REFRESH_COOKIE = process.env.AUTH_REFRESH_COOKIE_NAME || 'vdcms_refresh';
const CSRF_COOKIE = process.env.AUTH_CSRF_COOKIE_NAME || 'vdcms_csrf';
const ACCESS_TTL_SECONDS = Math.max(300, Number(process.env.AUTH_ACCESS_TTL_SECONDS || 900));
const REFRESH_TTL_SECONDS = Math.max(3600, Number(process.env.AUTH_REFRESH_TTL_SECONDS || 604800));
const JWT_ISSUER = 'vdcms';
const JWT_AUDIENCE = 'vdcms-web';

const refreshSecret = () => process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET;
const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

const parseCookies = (header = '') => header.split(';').reduce((cookies, part) => {
    const separator = part.indexOf('=');
    if (separator < 0) return cookies;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (!name) return cookies;
    try {
        cookies[name] = decodeURIComponent(value);
    } catch {
        cookies[name] = value;
    }
    return cookies;
}, {});

const getBearerToken = (authorization = '') => {
    const [scheme, token] = authorization.trim().split(/\s+/);
    return scheme?.toLowerCase() === 'bearer' && token ? token : null;
};

const extractAccessToken = (request) => {
    const cookies = parseCookies(request?.headers?.cookie || '');
    return getBearerToken(request?.headers?.authorization || '')
        || cookies[ACCESS_COOKIE]
        || null;
};

const extractRefreshToken = (request) => {
    const cookies = parseCookies(request?.headers?.cookie || '');
    return cookies[REFRESH_COOKIE] || null;
};

const cookieSecure = () => {
    if (process.env.AUTH_COOKIE_SECURE === 'true') return true;
    if (process.env.AUTH_COOKIE_SECURE === 'false') return false;
    return process.env.NODE_ENV === 'production';
};

const cookieSameSite = () => {
    const value = String(process.env.AUTH_COOKIE_SAMESITE || 'lax').toLowerCase();
    return ['strict', 'lax', 'none'].includes(value) ? value : 'lax';
};

const baseCookieOptions = () => ({
    httpOnly: true,
    secure: cookieSecure(),
    sameSite: cookieSameSite(),
    priority: 'high',
});

const createCsrfToken = () => crypto.randomBytes(32).toString('hex');

const setCsrfCookie = (res) => {
    res.cookie(CSRF_COOKIE, createCsrfToken(), {
        ...baseCookieOptions(),
        httpOnly: false,
        path: '/',
        maxAge: REFRESH_TTL_SECONDS * 1000,
    });
};

const setAuthCookies = (res, accessToken, refreshToken) => {
    res.cookie(ACCESS_COOKIE, accessToken, {
        ...baseCookieOptions(),
        path: '/',
        maxAge: ACCESS_TTL_SECONDS * 1000,
    });
    res.cookie(REFRESH_COOKIE, refreshToken, {
        ...baseCookieOptions(),
        path: '/api/auth',
        maxAge: REFRESH_TTL_SECONDS * 1000,
    });
    setCsrfCookie(res);
};

const clearAuthCookies = (res) => {
    res.clearCookie(ACCESS_COOKIE, { ...baseCookieOptions(), path: '/' });
    res.clearCookie(REFRESH_COOKIE, { ...baseCookieOptions(), path: '/api/auth' });
    res.clearCookie(CSRF_COOKIE, { ...baseCookieOptions(), httpOnly: false, path: '/' });
};

const signAccessToken = (user) => jwt.sign(
    {
        id: user.id,
        role: user.role,
        auth_version: Number(user.auth_version) || 0,
        token_type: 'access',
    },
    process.env.JWT_SECRET,
    {
        expiresIn: ACCESS_TTL_SECONDS,
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
        jwtid: crypto.randomUUID(),
    }
);

const signRefreshToken = (user) => jwt.sign(
    { id: user.id, token_type: 'refresh' },
    refreshSecret(),
    {
        expiresIn: REFRESH_TTL_SECONDS,
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
        jwtid: crypto.randomUUID(),
    }
);

const insertRefreshSession = async (executor, user, token, req) => {
    const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000);
    await executor.query(
        `INSERT INTO refresh_sessions
         (user_id, token_hash, expires_at, user_agent, ip_address)
         VALUES (?, ?, ?, ?, ?)`,
        [
            user.id,
            hashToken(token),
            expiresAt,
            String(req?.headers?.['user-agent'] || '').slice(0, 500) || null,
            String(req?.ip || req?.socket?.remoteAddress || '').slice(0, 64) || null,
        ]
    );
};

const createAuthSession = async (res, user, req) => {
    if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not configured.');
    const accessToken = signAccessToken(user);
    const refreshToken = signRefreshToken(user);
    await insertRefreshSession(db, user, refreshToken, req);
    setAuthCookies(res, accessToken, refreshToken);
};

const rotateAuthSession = async (req, res) => {
    const refreshToken = extractRefreshToken(req);
    if (!refreshToken) return null;

    let payload;
    try {
        payload = jwt.verify(refreshToken, refreshSecret(), {
            issuer: JWT_ISSUER,
            audience: JWT_AUDIENCE,
        });
        if (payload.token_type !== 'refresh' || !payload.id) return null;
    } catch {
        return null;
    }

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        const tokenHash = hashToken(refreshToken);
        const [rows] = await connection.query(
            `SELECT s.id AS session_id, s.user_id, s.revoked_at, s.expires_at,
                    u.username, u.fullname, u.email, u.role, u.status, u.auth_version, u.deleted_at
             FROM refresh_sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ? AND s.user_id = ?
             LIMIT 1 FOR UPDATE`,
            [tokenHash, payload.id]
        );

        const session = rows[0];
        const expiresAt = session ? new Date(session.expires_at) : null;
        if (!session || !expiresAt || Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date()) {
            await connection.rollback();
            return null;
        }
        if (session.revoked_at) {
            await connection.query(
                'UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = ?',
                [session.user_id]
            );
            await connection.commit();
            return null;
        }
        if (session.status !== 'active' || session.deleted_at) {
            await connection.query(
                'UPDATE refresh_sessions SET revoked_at = NOW() WHERE id = ?',
                [session.session_id]
            );
            await connection.commit();
            return null;
        }

        const user = {
            id: session.user_id,
            username: session.username,
            fullname: session.fullname,
            email: session.email,
            role: session.role,
            auth_version: Number(session.auth_version) || 0,
        };
        const accessToken = signAccessToken(user);
        const nextRefreshToken = signRefreshToken(user);
        const nextHash = hashToken(nextRefreshToken);

        await connection.query(
            'UPDATE refresh_sessions SET revoked_at = NOW(), replaced_by_hash = ? WHERE id = ?',
            [nextHash, session.session_id]
        );
        await insertRefreshSession(connection, user, nextRefreshToken, req);
        await connection.commit();

        setAuthCookies(res, accessToken, nextRefreshToken);
        return {
            id: user.id,
            username: user.username,
            fullname: user.fullname,
            email: user.email,
            role: user.role,
        };
    } catch (error) {
        await connection.rollback();
        throw error;
    } finally {
        connection.release();
    }
};

const revokeRequestSession = async (req) => {
    const refreshToken = extractRefreshToken(req);
    if (!refreshToken) return;
    await db.query(
        'UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE token_hash = ?',
        [hashToken(refreshToken)]
    );
};

const revokeUserSessions = async (userId, executor = db) => {
    await executor.query(
        'UPDATE refresh_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = ?',
        [userId]
    );
};

module.exports = {
    ACCESS_COOKIE,
    REFRESH_COOKIE,
    CSRF_COOKIE,
    JWT_ISSUER,
    JWT_AUDIENCE,
    parseCookies,
    extractAccessToken,
    setCsrfCookie,
    clearAuthCookies,
    createAuthSession,
    rotateAuthSession,
    revokeRequestSession,
    revokeUserSessions,
};
