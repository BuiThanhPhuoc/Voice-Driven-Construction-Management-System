const test = require('node:test');
const assert = require('node:assert/strict');

const dbPath = require.resolve('../config/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    exports: { query: async () => [], getConnection: async () => ({}) },
};

const csrfProtection = require('../middlewares/csrfMiddleware');
const { ACCESS_COOKIE, CSRF_COOKIE } = require('../utils/authSession');

const createResponse = () => ({
    statusCode: 200,
    body: null,
    status(code) {
        this.statusCode = code;
        return this;
    },
    json(payload) {
        this.body = payload;
        return this;
    },
});

const run = (request) => {
    const response = createResponse();
    let nextCalled = false;
    csrfProtection(
        {
            method: 'POST',
            headers: request.headers || {},
            get(name) {
                return this.headers[String(name).toLowerCase()];
            },
            ...request,
        },
        response,
        () => {
            nextCalled = true;
        }
    );
    return { response, nextCalled };
};

test('csrf protection allows matching double submit token', () => {
    const token = 'a'.repeat(64);
    const { response, nextCalled } = run({
        headers: {
            cookie: `${ACCESS_COOKIE}=access.${token}; ${CSRF_COOKIE}=${token}`,
            'x-csrf-token': token,
        },
    });
    assert.equal(nextCalled, true);
    assert.equal(response.statusCode, 200);
});

test('csrf protection blocks cookie session without csrf header', () => {
    const token = 'b'.repeat(64);
    const { response, nextCalled } = run({
        headers: {
            cookie: `${ACCESS_COOKIE}=access.${token}; ${CSRF_COOKIE}=${token}`,
        },
    });
    assert.equal(nextCalled, false);
    assert.equal(response.statusCode, 403);
    assert.equal(response.body.code, 'CSRF_TOKEN_INVALID');
});

test('csrf protection skips explicit bearer tokens for external auth compatibility', () => {
    const { response, nextCalled } = run({
        headers: {
            authorization: 'Bearer cognito-token',
        },
    });
    assert.equal(nextCalled, true);
    assert.equal(response.statusCode, 200);
});
