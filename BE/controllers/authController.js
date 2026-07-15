const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../config/db');
const {
    registerValidator,
    loginValidator,
    emailRequestValidator,
    tokenValidator,
    resetPasswordValidator,
} = require('../validations/authValidation');
const respondServerError = require('../utils/respondServerError');
const sendEmail = require('../utils/emailService');
const {
    clearAuthCookies,
    createAuthSession,
    rotateAuthSession,
    revokeRequestSession,
    revokeUserSessions,
    setCsrfCookie,
} = require('../utils/authSession');

const appUrl = () => (process.env.APP_URL || 'http://localhost:5173').replace(/\/$/, '');
const createToken = () => crypto.randomBytes(32).toString('hex');
const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');
const developmentToken = (key, token) => process.env.NODE_ENV === 'production' ? {} : { [key]: token };
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;',
})[character]);

const sendVerificationEmail = async (email, fullname, token) => {
    const url = `${appUrl()}/verify-email?token=${token}`;
    const safeName = escapeHtml(fullname);
    return sendEmail({
        to: email,
        subject: 'Xác thực email VDCMS',
        text: `Xin chào ${fullname}, mở liên kết sau để xác thực email: ${url}`,
        html: `<p>Xin chào ${safeName},</p><p>Vui lòng <a href="${url}">xác thực email VDCMS</a>. Liên kết có hiệu lực trong 24 giờ.</p>`,
    });
};

exports.register = async (req, res) => {
    try {
        const { error, value } = registerValidator(req.body);
        if (error) return res.status(400).json({ success: false, message: error.details[0].message });

        const [existingUser] = await db.query(
            'SELECT id FROM users WHERE email = ? OR username = ?',
            [value.email, value.username]
        );
        if (existingUser.length) {
            return res.status(409).json({ success: false, message: 'Username hoặc Email này đã tồn tại trên hệ thống!' });
        }

        const hashedPassword = await bcrypt.hash(value.password, 10);
        const verificationToken = createToken();
        await db.query(
            `INSERT INTO users
             (username, fullname, email, phone, password, role, status,
              verification_token_hash, verification_expires_at)
             VALUES (?, ?, ?, ?, ?, 'engineer', 'pending', ?, DATE_ADD(NOW(), INTERVAL 24 HOUR))`,
            [
                value.username,
                value.fullname,
                value.email,
                value.phone,
                hashedPassword,
                hashToken(verificationToken),
            ]
        );

        const delivery = await sendVerificationEmail(value.email, value.fullname, verificationToken);
        return res.status(201).json({
            success: true,
            email_sent: delivery.success,
            message: delivery.success
                ? 'Đã gửi đăng ký. Vui lòng xác thực email và chờ Admin phê duyệt.'
                : 'Tài khoản đã được tạo nhưng email xác thực chưa gửi được. Vui lòng thử gửi lại từ trang xác thực email.',
            ...developmentToken('dev_verification_token', verificationToken),
        });
    } catch (error) {
        return respondServerError(res, error);
    }
};

exports.login = async (req, res) => {
    try {
        const { error, value } = loginValidator(req.body);
        if (error) return res.status(400).json({ success: false, message: error.details[0].message });

        const [users] = await db.query(
            'SELECT * FROM users WHERE username = ? AND deleted_at IS NULL',
            [value.username]
        );
        if (!users.length || !(await bcrypt.compare(value.password, users[0].password))) {
            return res.status(400).json({ success: false, message: 'Tên đăng nhập hoặc mật khẩu không chính xác!' });
        }

        const user = users[0];
        if (user.status === 'pending') {
            return res.status(403).json({ success: false, code: 'ACCOUNT_PENDING', message: 'Tài khoản đang chờ Admin phê duyệt.' });
        }
        if (user.status === 'suspended' || user.status === 'inactive') {
            return res.status(403).json({ success: false, message: 'Tài khoản của bạn đã bị khóa.' });
        }
        if (!user.email_verified_at) {
            return res.status(403).json({ success: false, code: 'EMAIL_NOT_VERIFIED', message: 'Vui lòng xác thực email trước khi đăng nhập.' });
        }

        const sessionUser = {
            id: user.id,
            username: user.username,
            fullname: user.fullname,
            email: user.email,
            role: user.role,
            auth_version: Number(user.auth_version) || 0,
        };
        await createAuthSession(res, sessionUser, req);
        return res.status(200).json({
            success: true,
            message: 'Đăng nhập thành công!',
            user: {
                id: sessionUser.id,
                username: sessionUser.username,
                fullname: sessionUser.fullname,
                email: sessionUser.email,
                role: sessionUser.role,
            },
        });
    } catch (error) {
        return respondServerError(res, error);
    }
};

exports.refreshSession = async (req, res) => {
    try {
        const user = await rotateAuthSession(req, res);
        if (!user) {
            clearAuthCookies(res);
            return res.status(401).json({ success: false, message: 'Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.' });
        }
        return res.json({ success: true, user });
    } catch (error) {
        return respondServerError(res, error);
    }
};

exports.logout = async (req, res) => {
    try {
        await revokeRequestSession(req);
        clearAuthCookies(res);
        return res.json({ success: true, message: 'Đã đăng xuất an toàn.' });
    } catch (error) {
        clearAuthCookies(res);
        return respondServerError(res, error);
    }
};

exports.me = async (req, res) => {
    try {
        const [users] = await db.query(
            `SELECT id, username, fullname, email, role
             FROM users WHERE id = ? AND status = 'active' AND deleted_at IS NULL LIMIT 1`,
            [req.user.id]
        );
        if (!users.length) {
            clearAuthCookies(res);
            return res.status(401).json({ success: false, message: 'Phiên đăng nhập không còn hợp lệ.' });
        }
        setCsrfCookie(res);
        return res.json({ success: true, user: users[0] });
    } catch (error) {
        return respondServerError(res, error);
    }
};

exports.verifyEmail = async (req, res) => {
    try {
        const { error, value } = tokenValidator(req.body);
        if (error) return res.status(400).json({ success: false, message: 'Liên kết xác thực không hợp lệ.' });

        const [result] = await db.query(
            `UPDATE users
             SET email_verified_at = NOW(), verification_token_hash = NULL, verification_expires_at = NULL
             WHERE verification_token_hash = ? AND verification_expires_at > NOW() AND deleted_at IS NULL`,
            [hashToken(value.token)]
        );
        if (!result.affectedRows) {
            return res.status(400).json({ success: false, message: 'Liên kết xác thực đã hết hạn hoặc không hợp lệ.' });
        }
        return res.json({ success: true, message: 'Email đã được xác thực. Tài khoản sẽ sử dụng được sau khi Admin phê duyệt.' });
    } catch (error) {
        return respondServerError(res, error);
    }
};

exports.resendVerification = async (req, res) => {
    try {
        const { error, value } = emailRequestValidator(req.body);
        if (error) return res.status(400).json({ success: false, message: 'Email không hợp lệ.' });
        const [users] = await db.query(
            'SELECT id, fullname, email, email_verified_at FROM users WHERE email = ? AND deleted_at IS NULL LIMIT 1',
            [value.email]
        );
        const genericMessage = 'Nếu email tồn tại và chưa xác thực, hệ thống đã gửi một liên kết mới.';
        if (!users.length || users[0].email_verified_at) return res.json({ success: true, message: genericMessage });

        const token = createToken();
        await db.query(
            `UPDATE users SET verification_token_hash = ?, verification_expires_at = DATE_ADD(NOW(), INTERVAL 24 HOUR)
             WHERE id = ?`,
            [hashToken(token), users[0].id]
        );
        await sendVerificationEmail(users[0].email, users[0].fullname, token);
        return res.json({ success: true, message: genericMessage, ...developmentToken('dev_verification_token', token) });
    } catch (error) {
        return respondServerError(res, error);
    }
};

exports.forgotPassword = async (req, res) => {
    try {
        const { error, value } = emailRequestValidator(req.body);
        if (error) return res.status(400).json({ success: false, message: 'Email không hợp lệ.' });
        const [users] = await db.query(
            `SELECT id, fullname, email FROM users
             WHERE email = ? AND deleted_at IS NULL AND status <> 'suspended' LIMIT 1`,
            [value.email]
        );
        const genericMessage = 'Nếu email tồn tại, hệ thống đã gửi hướng dẫn đặt lại mật khẩu.';
        if (!users.length) return res.json({ success: true, message: genericMessage });

        const token = createToken();
        await db.query(
            `UPDATE users SET reset_token_hash = ?, reset_expires_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE)
             WHERE id = ?`,
            [hashToken(token), users[0].id]
        );
        const url = `${appUrl()}/reset-password?token=${token}`;
        await sendEmail({
            to: users[0].email,
            subject: 'Đặt lại mật khẩu VDCMS',
            text: `Xin chào ${users[0].fullname}, đặt lại mật khẩu tại: ${url}`,
            html: `<p>Xin chào ${escapeHtml(users[0].fullname)},</p><p><a href="${url}">Đặt lại mật khẩu</a>. Liên kết có hiệu lực trong 30 phút.</p>`,
        });
        return res.json({ success: true, message: genericMessage, ...developmentToken('dev_reset_token', token) });
    } catch (error) {
        return respondServerError(res, error);
    }
};

exports.resetPassword = async (req, res) => {
    try {
        const { error, value } = resetPasswordValidator(req.body);
        if (error) return res.status(400).json({ success: false, message: error.details[0].message });
        const [users] = await db.query(
            `SELECT id, password FROM users
             WHERE reset_token_hash = ? AND reset_expires_at > NOW() AND deleted_at IS NULL LIMIT 1`,
            [hashToken(value.token)]
        );
        if (!users.length) return res.status(400).json({ success: false, message: 'Liên kết đặt lại mật khẩu đã hết hạn hoặc không hợp lệ.' });
        if (await bcrypt.compare(value.password, users[0].password)) {
            return res.status(400).json({ success: false, message: 'Mật khẩu mới phải khác mật khẩu hiện tại.' });
        }

        const passwordHash = await bcrypt.hash(value.password, 10);
        await db.query(
            `UPDATE users
             SET password = ?, reset_token_hash = NULL, reset_expires_at = NULL,
                 auth_version = auth_version + 1
             WHERE id = ?`,
            [passwordHash, users[0].id]
        );
        await revokeUserSessions(users[0].id);
        clearAuthCookies(res);
        return res.json({ success: true, message: 'Đặt lại mật khẩu thành công. Bạn có thể đăng nhập bằng mật khẩu mới.' });
    } catch (error) {
        return respondServerError(res, error);
    }
};
