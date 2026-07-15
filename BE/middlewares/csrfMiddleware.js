const { ACCESS_COOKIE, CSRF_COOKIE, parseCookies } = require('../utils/authSession');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

const getBearerToken = (authorization = '') => {
    const [scheme, token] = String(authorization).trim().split(/\s+/);
    return scheme?.toLowerCase() === 'bearer' && token ? token : null;
};

const csrfProtection = (req, res, next) => {
    if (SAFE_METHODS.has(req.method)) return next();

    const cookies = parseCookies(req.headers.cookie || '');
    const hasCookieSession = Boolean(cookies[ACCESS_COOKIE]);
    const hasExplicitBearerToken = Boolean(getBearerToken(req.headers.authorization || ''));

    if (!hasCookieSession || hasExplicitBearerToken) return next();

    const csrfCookie = cookies[CSRF_COOKIE];
    const csrfHeader = req.get('x-csrf-token');

    if (csrfCookie && csrfHeader && csrfCookie === csrfHeader) return next();

    return res.status(403).json({
        success: false,
        code: 'CSRF_TOKEN_INVALID',
        message: 'Yêu cầu bảo mật không hợp lệ. Vui lòng tải lại trang rồi thử lại.',
    });
};

module.exports = csrfProtection;
