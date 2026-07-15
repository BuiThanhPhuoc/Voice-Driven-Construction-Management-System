const express = require('express');

const http = require('http');

const path = require('path');

const dotenv = require('dotenv');

const cors = require('cors');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');



dotenv.config();



const db = require('./config/db');

const initChatTables = require('./config/initChat');
const initCoreSchema = require('./config/initCoreSchema');
const initApplication = require('./config/initApplication');
const bootstrapAdmin = require('./config/bootstrapAdmin');

const initSocket = require('./socket');
const { corsOptions } = require('./config/security');
const csrfProtection = require('./middlewares/csrfMiddleware');

const authRouter = require('./routers/authRouter');

const userRouter = require('./routers/userRouter');

const projectRouter = require('./routers/projectRouter');

const taskRouter = require('./routers/taskRouter');

const reportRouter = require('./routers/reportRouter');

const chatRouter = require('./routers/chatRouter');
const notificationRouter = require('./routers/notificationRouter');
const activityRouter = require('./routers/activityRouter');
const publicRouter = require('./routers/publicRouter');
const contactRouter = require('./routers/contactRouter');
const taskRequestRouter = require('./routers/taskRequestRouter');
const incidentRouter = require('./routers/incidentRouter');
const documentRouter = require('./routers/documentRouter');
const managerRouter = require('./routers/managerRouter');
const awsRouter = require('./routers/awsRouter');
const managerAssignmentRouter = require('./routers/managerAssignmentRouter');
const userDeletionRouter = require('./routers/userDeletionRouter');



const app = express();

if (process.env.NODE_ENV === 'production') {
    app.set('trust proxy', Math.max(1, Number(process.env.TRUST_PROXY_HOPS || 1)));
}

const server = http.createServer(app);

server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`Cổng ${process.env.PORT || 5000} đang được một tiến trình khác sử dụng. Hãy dừng backend cũ rồi chạy lại npm start.`);
        process.exit(1);
    }
    console.error('Không thể khởi động máy chủ:', error.message);
    process.exit(1);
});



app.disable('x-powered-by');
app.use(helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
}));
app.use(cors(corsOptions));

app.use(express.json({ limit: '100kb' }));
app.use('/api', csrfProtection);

app.get('/health', async (_req, res) => {
    try {
        await db.query('SELECT 1');
        return res.status(200).json({ success: true, service: 'vdcms-backend', database: 'reachable' });
    } catch {
        return res.status(503).json({ success: false, service: 'vdcms-backend', database: 'unreachable' });
    }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));



const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { success: false, message: 'Bạn thao tác quá nhanh. Vui lòng thử lại sau.' },
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: { success: false, message: 'Quá nhiều lần thử đăng nhập. Vui lòng thử lại sau.' },
});

const registrationLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 5,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { success: false, message: 'Đã vượt quá số lần đăng ký cho phép. Vui lòng thử lại sau.' },
});

const contactLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { success: false, message: 'Bạn đã gửi quá nhiều yêu cầu liên hệ. Vui lòng thử lại sau.' },
});

app.use('/api', apiLimiter);
app.use('/api/auth/register', registrationLimiter);
app.use('/api/auth', authLimiter, authRouter);
app.use('/api/public/contact', contactLimiter);
app.use('/api/public', publicRouter);

app.use('/api/users', userRouter);

app.use('/api/projects', projectRouter);

app.use('/api/tasks', taskRouter);

app.use('/api/reports', reportRouter);

app.use('/api/chat', chatRouter);
app.use('/api/notifications', notificationRouter);
app.use('/api/activity-logs', activityRouter);
app.use('/api/contact-requests', contactRouter);
app.use('/api/task-requests', taskRequestRouter);
app.use('/api/incidents', incidentRouter);
app.use('/api/documents', documentRouter);
app.use('/api/manager', managerRouter);
app.use('/api/aws', awsRouter);
app.use('/api/manager-assignments', managerAssignmentRouter);
app.use('/api/user-deletions', userDeletionRouter);



app.get('/', (req, res) => {

    res.status(200).json({ success: true, message: "🚀 Hệ thống Backend đang hoạt động ổn định!" });

});

app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Không tìm thấy tài nguyên.' });
});

app.use((error, req, res, _next) => {
    console.error('Unhandled request error:', error);
    const isUploadLimit = error?.code === 'LIMIT_FILE_SIZE';
    const isInvalidFileType = error?.message === 'Chỉ chấp nhận file âm thanh.';
    const isInvalidReportFile = error?.message === 'Chỉ chấp nhận ảnh JPG, PNG, WEBP hoặc tài liệu PDF.';
    const isInvalidChatFile = error?.message === 'Định dạng file chat không được hỗ trợ.';
    const isInvalidIncidentFile = error?.message === 'Minh chứng sự cố chỉ chấp nhận JPG, PNG hoặc WEBP.';
    const isInvalidDocument = error?.message === 'Định dạng tài liệu không được hỗ trợ.';
    const isInvalidTranscribeFile = error?.message === 'Định dạng âm thanh Transcribe không được hỗ trợ.';
    const status = error?.status || (isUploadLimit ? 413 : (isInvalidFileType || isInvalidReportFile || isInvalidChatFile || isInvalidIncidentFile || isInvalidDocument || isInvalidTranscribeFile) ? 400 : 500);
    res.status(status).json({
        success: false,
        message: isUploadLimit
            ? req.originalUrl.startsWith('/api/documents')
                ? 'Tài liệu tải lên vượt quá giới hạn 25 MB.'
                : req.originalUrl.startsWith('/api/incidents')
                    ? 'Ảnh sự cố vượt quá giới hạn 8 MB.'
                    : req.originalUrl.startsWith('/api/chat')
                        ? 'File chat vượt quá giới hạn 15 MB.'
                        : 'File tải lên vượt quá giới hạn 10 MB.'
            : isInvalidFileType
                ? error.message
                : isInvalidReportFile
                    ? error.message
                : isInvalidChatFile
                    ? error.message
                : isInvalidIncidentFile || isInvalidDocument || isInvalidTranscribeFile
                    ? error.message
                : status === 403
                    ? 'Nguồn truy cập không được phép.'
            : 'Máy chủ gặp lỗi. Vui lòng thử lại sau.',
    });
});



const PORT = process.env.PORT || 5000;



const startServer = async () => {

    try {

        await initCoreSchema();
        await initApplication();

        await initChatTables();
        await bootstrapAdmin();

        const io = initSocket(server);
        app.set('io', io);

        server.listen(PORT, () => {

            console.log(`\n🚀 Server khởi động tại Port: ${PORT}\n`);

        });

    } catch (error) {

        console.error('Không thể khởi động server:', error.message);

        process.exit(1);

    }

};



startServer();
