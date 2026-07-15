const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'access-secret-for-tests-that-is-long-enough';
process.env.JWT_REFRESH_SECRET = 'refresh-secret-for-tests-that-is-different';
process.env.AUTH_ACCESS_TTL_SECONDS = '900';
process.env.AUTH_REFRESH_TTL_SECONDS = '7200';

const users = new Map([
    [1, {
        id: 1,
        username: 'engineer01',
        fullname: 'Engineer Test',
        email: 'engineer@example.com',
        role: 'engineer',
        status: 'active',
        deleted_at: null,
    }],
]);
const sessions = [];

const query = async (sql, values = []) => {
    if (sql.includes('INSERT INTO refresh_sessions')) {
        sessions.push({
            id: sessions.length + 1,
            user_id: values[0],
            token_hash: values[1],
            expires_at: values[2],
            user_agent: values[3],
            ip_address: values[4],
            revoked_at: null,
            replaced_by_hash: null,
        });
        return [{ insertId: sessions.length }];
    }
    if (sql.includes('FROM refresh_sessions s')) {
        const session = sessions.find((entry) => entry.token_hash === values[0] && entry.user_id === values[1]);
        if (!session) return [[]];
        const user = users.get(session.user_id);
        return [[{
            session_id: session.id,
            user_id: session.user_id,
            revoked_at: session.revoked_at,
            expires_at: session.expires_at,
            ...user,
        }]];
    }
    if (sql.includes('replaced_by_hash = ?')) {
        const session = sessions.find((entry) => entry.id === values[1]);
        session.revoked_at = new Date();
        session.replaced_by_hash = values[0];
        return [{ affectedRows: 1 }];
    }
    if (sql.includes('WHERE token_hash = ?')) {
        const session = sessions.find((entry) => entry.token_hash === values[0]);
        if (session && !session.revoked_at) session.revoked_at = new Date();
        return [{ affectedRows: session ? 1 : 0 }];
    }
    if (sql.includes('WHERE user_id = ?')) {
        sessions.filter((entry) => entry.user_id === values[0] && !entry.revoked_at)
            .forEach((entry) => { entry.revoked_at = new Date(); });
        return [{ affectedRows: 1 }];
    }
    if (sql.includes('WHERE id = ?')) {
        const session = sessions.find((entry) => entry.id === values[0]);
        if (session) session.revoked_at = new Date();
        return [{ affectedRows: session ? 1 : 0 }];
    }
    throw new Error(`Unexpected test query: ${sql}`);
};

const fakeDb = {
    query,
    async getConnection() {
        return {
            query,
            beginTransaction: async () => {},
            commit: async () => {},
            rollback: async () => {},
            release: () => {},
        };
    },
};

const dbPath = require.resolve('../config/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    exports: fakeDb,
};

const {
    ACCESS_COOKIE,
    REFRESH_COOKIE,
    CSRF_COOKIE,
    createAuthSession,
    extractAccessToken,
    rotateAuthSession,
} = require('../utils/authSession');

const createResponse = () => ({
    values: new Map(),
    cookie(name, value, options) {
        this.values.set(name, { value, options });
    },
    clearCookie(name, options) {
        this.values.set(name, { value: null, options });
    },
});

test('login session stores JWTs only in HttpOnly SameSite cookies', async () => {
    sessions.length = 0;
    const response = createResponse();
    await createAuthSession(response, users.get(1), {
        headers: { 'user-agent': 'node-test' },
        ip: '127.0.0.1',
    });

    const access = response.values.get(ACCESS_COOKIE);
    const refresh = response.values.get(REFRESH_COOKIE);
    const csrf = response.values.get(CSRF_COOKIE);
    assert.equal(access.options.httpOnly, true);
    assert.equal(access.options.sameSite, 'lax');
    assert.equal(access.options.path, '/');
    assert.equal(refresh.options.httpOnly, true);
    assert.equal(refresh.options.path, '/api/auth');
    assert.equal(csrf.options.httpOnly, false);
    assert.equal(csrf.options.path, '/');
    assert.match(csrf.value, /^[a-f0-9]{64}$/);
    assert.equal(sessions.length, 1);

    const accessPayload = jwt.verify(access.value, process.env.JWT_SECRET, {
        issuer: 'vdcms', audience: 'vdcms-web',
    });
    assert.equal(accessPayload.token_type, 'access');
    assert.equal(accessPayload.id, 1);
    assert.equal(accessPayload.auth_version, 0);
});

test('refresh token is rotated and cannot remain active after use', async () => {
    sessions.length = 0;
    const loginResponse = createResponse();
    await createAuthSession(loginResponse, users.get(1), { headers: {}, ip: '127.0.0.1' });
    const firstRefresh = loginResponse.values.get(REFRESH_COOKIE).value;

    const refreshResponse = createResponse();
    const user = await rotateAuthSession({
        headers: { cookie: `${REFRESH_COOKIE}=${encodeURIComponent(firstRefresh)}` },
        ip: '127.0.0.1',
    }, refreshResponse);

    const nextRefresh = refreshResponse.values.get(REFRESH_COOKIE).value;
    assert.equal(user.id, 1);
    assert.notEqual(nextRefresh, firstRefresh);
    assert.equal(sessions.length, 2);
    assert.ok(sessions[0].revoked_at);
    assert.equal(sessions[1].revoked_at, null);
});

test('access-token extraction supports HttpOnly cookie and explicit Cognito Bearer token', () => {
    assert.equal(
        extractAccessToken({ headers: { cookie: `${ACCESS_COOKIE}=cookie-token`, authorization: 'Bearer bearer-token' } }),
        'bearer-token'
    );
    assert.equal(
        extractAccessToken({ headers: { authorization: 'Bearer cognito-token' } }),
        'cognito-token'
    );
});
