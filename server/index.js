const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const redis = require('redis');
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const passport = require('passport');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const hpp = require('hpp');
const morgan = require('morgan');
const winston = require('winston');
const cluster = require('cluster');
const os = require('os');
const path = require('path');
const fs = require('fs-extra');
const Bull = require('bull');
const cron = require('node-cron');
const { ApolloServer } = require('apollo-server-express');
const { buildSchema } = require('graphql');
const { createProxyMiddleware } = require('http-proxy-middleware');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const prometheus = require('prom-client');
const jaeger = require('jaeger-client');
const Sentry = require('@sentry/node');
const newrelic = require('newrelic');

const config = require('./config');
const logger = require('./utils/logger');
const database = require('./database');
const cache = require('./cache');
const auth = require('./middleware/auth');
const validation = require('./middleware/validation');
const errorHandler = require('./middleware/errorHandler');
const rateLimiter = require('./middleware/rateLimiter');
const security = require('./middleware/security');
const monitoring = require('./middleware/monitoring');
const websocket = require('./websocket');
const graphql = require('./graphql');
const jobs = require('./jobs');
const services = require('./services');
const routes = require('./routes');
const models = require('./models');
const controllers = require('./controllers');
const utils = require('./utils');

class EnterpriseServer {
    constructor() {
        this.app = express();
        this.server = http.createServer(this.app);
        this.io = socketIo(this.server, {
            cors: {
                origin: config.client.url,
                methods: ['GET', 'POST'],
                credentials: true
            },
            transports: ['websocket', 'polling'],
            pingTimeout: 60000,
            pingInterval: 25000
        });
        
        this.redisClient = null;
        this.apolloServer = null;
        this.jobQueues = new Map();
        this.metrics = this.initializeMetrics();
        this.tracer = this.initializeTracing();
        
        this.isShuttingDown = false;
        this.connections = new Set();
        this.workers = new Map();
        
        this.initializeErrorHandling();
        this.initializeGracefulShutdown();
    }

    async initialize() {
        try {
            logger.info('Initializing Enterprise Server...');
            
            await this.connectDatabases();
            await this.setupMiddleware();
            await this.setupAuthentication();
            await this.setupRoutes();
            await this.setupGraphQL();
            await this.setupWebSocket();
            await this.setupJobQueues();
            await this.setupCronJobs();
            await this.setupMonitoring();
            await this.setupDocumentation();
            
            logger.info('Enterprise Server initialized successfully');
        } catch (error) {
            logger.error('Failed to initialize server:', error);
            throw error;
        }
    }

    async connectDatabases() {
        try {
            await database.connectMongoDB();
            await database.connectPostgreSQL();
            await database.connectRedis();
            
            this.redisClient = cache.getClient();
            
            logger.info('All databases connected successfully');
        } catch (error) {
            logger.error('Database connection failed:', error);
            throw error;
        }
    }

    async setupMiddleware() {
        Sentry.init({
            dsn: config.sentry.dsn,
            environment: config.env,
            tracesSampleRate: 1.0
        });

        this.app.use(Sentry.Handlers.requestHandler());
        this.app.use(Sentry.Handlers.tracingHandler());

        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                    fontSrc: ["'self'", "https://fonts.gstatic.com"],
                    scriptSrc: ["'self'", "'unsafe-inline'"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'", "ws:", "wss:"]
                }
            },
            crossOriginEmbedderPolicy: false
        }));

        this.app.use(cors({
            origin: config.cors.origins,
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
        }));

        this.app.use(compression({
            level: 6,
            threshold: 1024,
            filter: (req, res) => {
                if (req.headers['x-no-compression']) return false;
                return compression.filter(req, res);
            }
        }));

        this.app.use(express.json({ 
            limit: '50mb',
            verify: (req, res, buf) => {
                req.rawBody = buf;
            }
        }));
        
        this.app.use(express.urlencoded({ 
            extended: true, 
            limit: '50mb' 
        }));

        this.app.use(mongoSanitize());
        this.app.use(hpp());

        this.app.use((req, res, next) => {
            req.body = this.sanitizeInput(req.body);
            req.query = this.sanitizeInput(req.query);
            req.params = this.sanitizeInput(req.params);
            next();
        });

        this.app.use(session({
            store: new RedisStore({ client: this.redisClient }),
            secret: config.session.secret,
            resave: false,
            saveUninitialized: false,
            rolling: true,
            cookie: {
                secure: config.env === 'production',
                httpOnly: true,
                maxAge: config.session.maxAge,
                sameSite: 'lax'
            }
        }));

        this.app.use(morgan('combined', {
            stream: {
                write: (message) => logger.info(message.trim())
            }
        }));

        this.app.use(rateLimiter.global);
        this.app.use(monitoring.requestMetrics);
        this.app.use(security.csrfProtection);

        this.app.use((req, res, next) => {
            req.startTime = Date.now();
            req.requestId = utils.generateId();
            res.locals.requestId = req.requestId;
            
            this.connections.add(req);
            res.on('finish', () => {
                this.connections.delete(req);
            });
            
            next();
        });
    }

    async setupAuthentication() {
        this.app.use(passport.initialize());
        this.app.use(passport.session());

        await auth.configureStrategies(passport);

        this.app.use('/auth', routes.auth);
        this.app.use('/oauth', routes.oauth);
    }

    async setupRoutes() {
        this.app.use('/api/v1/users', auth.authenticate, routes.users);
        this.app.use('/api/v1/organizations', auth.authenticate, routes.organizations);
        this.app.use('/api/v1/projects', auth.authenticate, routes.projects);
        this.app.use('/api/v1/tasks', auth.authenticate, routes.tasks);
        this.app.use('/api/v1/analytics', auth.authenticate, routes.analytics);
        this.app.use('/api/v1/reports', auth.authenticate, routes.reports);
        this.app.use('/api/v1/notifications', auth.authenticate, routes.notifications);
        this.app.use('/api/v1/files', auth.authenticate, routes.files);
        this.app.use('/api/v1/integrations', auth.authenticate, routes.integrations);
        this.app.use('/api/v1/workflows', auth.authenticate, routes.workflows);
        this.app.use('/api/v1/automation', auth.authenticate, routes.automation);
        this.app.use('/api/v1/billing', auth.authenticate, routes.billing);
        this.app.use('/api/v1/admin', auth.authenticate, auth.requireRole('admin'), routes.admin);

        this.app.use('/api/v1/public', rateLimiter.public, routes.public);
        this.app.use('/api/v1/webhooks', rateLimiter.webhooks, routes.webhooks);

        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                cpu: process.cpuUsage(),
                version: require('../package.json').version,
                environment: config.env,
                services: {
                    mongodb: mongoose.connection.readyState === 1,
                    redis: this.redisClient?.status === 'ready',
                    postgresql: database.isPostgreSQLConnected()
                }
            });
        });

        this.app.get('/metrics', (req, res) => {
            res.set('Content-Type', prometheus.register.contentType);
            res.end(prometheus.register.metrics());
        });

        this.app.use('/status', require('express-status-monitor')({
            title: 'Enterprise Platform Status',
            path: '/status',
            spans: [
                { interval: 1, retention: 60 },
                { interval: 5, retention: 60 },
                { interval: 15, retention: 60 }
            ],
            chartVisibility: {
                cpu: true,
                mem: true,
                load: true,
                responseTime: true,
                rps: true,
                statusCodes: true
            },
            healthChecks: [
                {
                    protocol: 'http',
                    host: 'localhost',
                    path: '/health',
                    port: config.server.port
                }
            ]
        }));

        if (config.env === 'production') {
            this.app.use(express.static(path.join(__dirname, '../client/build')));
            
            this.app.get('*', (req, res) => {
                if (req.path.startsWith('/api/') || req.path.startsWith('/graphql') || req.path.startsWith('/socket.io/')) {
                    return res.status(404).json({ error: 'API endpoint not found' });
                }
                res.sendFile(path.join(__dirname, '../client/build/index.html'));
            });
        }
    }

    async setupGraphQL() {
        this.apolloServer = new ApolloServer({
            typeDefs: graphql.typeDefs,
            resolvers: graphql.resolvers,
            context: ({ req, res }) => ({
                req,
                res,
                user: req.user,
                dataSources: graphql.dataSources,
                cache: cache,
                logger: logger
            }),
            plugins: [
                {
                    requestDidStart() {
                        return {
                            willSendResponse(requestContext) {
                                const { response, request } = requestContext;
                                logger.info('GraphQL Query:', {
                                    query: request.query,
                                    variables: request.variables,
                                    operationName: request.operationName,
                                    responseTime: Date.now() - request.startTime
                                });
                            }
                        };
                    }
                }
            ],
            introspection: config.env !== 'production',
            playground: config.env !== 'production',
            formatError: (error) => {
                logger.error('GraphQL Error:', error);
                return {
                    message: error.message,
                    code: error.extensions?.code,
                    path: error.path
                };
            }
        });

        await this.apolloServer.start();
        this.apolloServer.applyMiddleware({ 
            app: this.app, 
            path: '/graphql',
            cors: false
        });
    }

    async setupWebSocket() {
        websocket.initialize(this.io);

        this.io.use(auth.socketAuthentication);

        this.io.on('connection', (socket) => {
            logger.info(`WebSocket connection established: ${socket.id}`);

            socket.on('join_room', (room) => {
                socket.join(room);
                logger.info(`Socket ${socket.id} joined room: ${room}`);
            });

            socket.on('leave_room', (room) => {
                socket.leave(room);
                logger.info(`Socket ${socket.id} left room: ${room}`);
            });

            socket.on('subscribe_analytics', (filters) => {
                websocket.subscribeToAnalytics(socket, filters);
            });

            socket.on('subscribe_notifications', (userId) => {
                websocket.subscribeToNotifications(socket, userId);
            });

            socket.on('real_time_collaboration', (data) => {
                websocket.handleCollaboration(socket, data);
            });

            socket.on('disconnect', (reason) => {
                logger.info(`WebSocket disconnected: ${socket.id}, reason: ${reason}`);
                websocket.handleDisconnection(socket);
            });

            socket.on('error', (error) => {
                logger.error(`WebSocket error for ${socket.id}:`, error);
            });
        });
    }

    async setupJobQueues() {
        const queueNames = [
            'email',
            'notifications',
            'analytics',
            'reports',
            'file-processing',
            'data-export',
            'backup',
            'cleanup',
            'integrations',
            'webhooks'
        ];

        for (const queueName of queueNames) {
            const queue = new Bull(queueName, {
                redis: {
                    host: config.redis.host,
                    port: config.redis.port,
                    password: config.redis.password
                },
                defaultJobOptions: {
                    removeOnComplete: 100,
                    removeOnFail: 50,
                    attempts: 3,
                    backoff: {
                        type: 'exponential',
                        delay: 2000
                    }
                }
            });

            queue.on('completed', (job) => {
                logger.info(`Job completed: ${job.id} in queue: ${queueName}`);
            });

            queue.on('failed', (job, err) => {
                logger.error(`Job failed: ${job.id} in queue: ${queueName}`, err);
            });

            queue.on('stalled', (job) => {
                logger.warn(`Job stalled: ${job.id} in queue: ${queueName}`);
            });

            this.jobQueues.set(queueName, queue);
        }

        await jobs.setupProcessors(this.jobQueues);
    }

    async setupCronJobs() {
        cron.schedule('0 2 * * *', async () => {
            logger.info('Running daily backup job');
            await this.jobQueues.get('backup').add('daily-backup', {
                timestamp: new Date().toISOString()
            });
        });

        cron.schedule('0 3 * * *', async () => {
            logger.info('Running daily cleanup job');
            await this.jobQueues.get('cleanup').add('daily-cleanup', {
                timestamp: new Date().toISOString()
            });
        });

        cron.schedule('*/15 * * * *', async () => {
            await this.jobQueues.get('analytics').add('update-metrics', {
                timestamp: new Date().toISOString()
            });
        });

        cron.schedule('0 */6 * * *', async () => {
            await this.jobQueues.get('integrations').add('sync-external-data', {
                timestamp: new Date().toISOString()
            });
        });

        cron.schedule('0 1 * * 1', async () => {
            logger.info('Running weekly reports job');
            await this.jobQueues.get('reports').add('weekly-reports', {
                timestamp: new Date().toISOString()
            });
        });
    }

    async setupMonitoring() {
        prometheus.collectDefaultMetrics({
            timeout: 10000,
            gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5],
            eventLoopMonitoringPrecision: 5
        });

        this.metrics.httpRequestDuration = new prometheus.Histogram({
            name: 'http_request_duration_seconds',
            help: 'Duration of HTTP requests in seconds',
            labelNames: ['method', 'route', 'status_code'],
            buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
        });

        this.metrics.httpRequestTotal = new prometheus.Counter({
            name: 'http_requests_total',
            help: 'Total number of HTTP requests',
            labelNames: ['method', 'route', 'status_code']
        });

        this.metrics.websocketConnections = new prometheus.Gauge({
            name: 'websocket_connections_total',
            help: 'Total number of WebSocket connections'
        });

        this.metrics.jobsProcessed = new prometheus.Counter({
            name: 'jobs_processed_total',
            help: 'Total number of jobs processed',
            labelNames: ['queue', 'status']
        });

        this.metrics.databaseQueries = new prometheus.Counter({
            name: 'database_queries_total',
            help: 'Total number of database queries',
            labelNames: ['database', 'operation']
        });

        this.app.use((req, res, next) => {
            const start = Date.now();
            
            res.on('finish', () => {
                const duration = (Date.now() - start) / 1000;
                const route = req.route ? req.route.path : req.path;
                
                this.metrics.httpRequestDuration
                    .labels(req.method, route, res.statusCode)
                    .observe(duration);
                
                this.metrics.httpRequestTotal
                    .labels(req.method, route, res.statusCode)
                    .inc();
            });
            
            next();
        });

        setInterval(() => {
            this.metrics.websocketConnections.set(this.io.engine.clientsCount);
        }, 5000);
    }

    async setupDocumentation() {
        const swaggerOptions = {
            definition: {
                openapi: '3.0.0',
                info: {
                    title: 'Enterprise Platform API',
                    version: '1.0.0',
                    description: 'Comprehensive API documentation for Enterprise Platform',
                    contact: {
                        name: 'API Support',
                        email: 'api-support@enterprise-platform.com'
                    }
                },
                servers: [
                    {
                        url: `http://localhost:${config.server.port}`,
                        description: 'Development server'
                    },
                    {
                        url: 'https://api.enterprise-platform.com',
                        description: 'Production server'
                    }
                ],
                components: {
                    securitySchemes: {
                        bearerAuth: {
                            type: 'http',
                            scheme: 'bearer',
                            bearerFormat: 'JWT'
                        }
                    }
                },
                security: [
                    {
                        bearerAuth: []
                    }
                ]
            },
            apis: ['./server/routes/*.js', './server/models/*.js']
        };

        const swaggerSpec = swaggerJsdoc(swaggerOptions);

        this.app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
            explorer: true,
            customCss: '.swagger-ui .topbar { display: none }',
            customSiteTitle: 'Enterprise Platform API Documentation'
        }));

        this.app.get('/api-docs.json', (req, res) => {
            res.setHeader('Content-Type', 'application/json');
            res.send(swaggerSpec);
        });
    }

    initializeMetrics() {
        return {
            httpRequestDuration: null,
            httpRequestTotal: null,
            websocketConnections: null,
            jobsProcessed: null,
            databaseQueries: null
        };
    }

    initializeTracing() {
        const config = {
            serviceName: 'enterprise-platform',
            sampler: {
                type: 'const',
                param: 1
            },
            reporter: {
                logSpans: true,
                agentHost: process.env.JAEGER_AGENT_HOST || 'localhost',
                agentPort: process.env.JAEGER_AGENT_PORT || 6832
            }
        };

        return jaeger.initTracer(config);
    }

    initializeErrorHandling() {
        process.on('uncaughtException', (error) => {
            logger.error('Uncaught Exception:', error);
            this.gracefulShutdown('SIGTERM');
        });

        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
        });

        this.app.use(Sentry.Handlers.errorHandler());
        this.app.use(errorHandler);
    }

    initializeGracefulShutdown() {
        const signals = ['SIGTERM', 'SIGINT', 'SIGUSR2'];
        
        signals.forEach((signal) => {
            process.on(signal, () => {
                this.gracefulShutdown(signal);
            });
        });
    }

    async gracefulShutdown(signal) {
        if (this.isShuttingDown) return;
        
        this.isShuttingDown = true;
        logger.info(`Received ${signal}. Starting graceful shutdown...`);

        const shutdownTimeout = setTimeout(() => {
            logger.error('Graceful shutdown timeout. Forcing exit.');
            process.exit(1);
        }, 30000);

        try {
            this.server.close(() => {
                logger.info('HTTP server closed');
            });

            this.io.close(() => {
                logger.info('WebSocket server closed');
            });

            for (const [name, queue] of this.jobQueues) {
                await queue.close();
                logger.info(`Job queue ${name} closed`);
            }

            if (this.redisClient) {
                await this.redisClient.quit();
                logger.info('Redis connection closed');
            }

            await mongoose.connection.close();
            logger.info('MongoDB connection closed');

            await database.closePostgreSQL();
            logger.info('PostgreSQL connection closed');

            clearTimeout(shutdownTimeout);
            logger.info('Graceful shutdown completed');
            process.exit(0);
        } catch (error) {
            logger.error('Error during graceful shutdown:', error);
            clearTimeout(shutdownTimeout);
            process.exit(1);
        }
    }

    sanitizeInput(obj) {
        if (typeof obj === 'string') {
            return xss(obj);
        }
        
        if (Array.isArray(obj)) {
            return obj.map(item => this.sanitizeInput(item));
        }
        
        if (obj && typeof obj === 'object') {
            const sanitized = {};
            for (const [key, value] of Object.entries(obj)) {
                sanitized[key] = this.sanitizeInput(value);
            }
            return sanitized;
        }
        
        return obj;
    }

    async start(port = config.server.port) {
        try {
            await this.initialize();
            
            this.server.listen(port, () => {
                logger.info(`Enterprise Platform Server started on port ${port}`);
                logger.info(`Environment: ${config.env}`);
                logger.info(`Process ID: ${process.pid}`);
                logger.info(`GraphQL endpoint: http://localhost:${port}/graphql`);
                logger.info(`API documentation: http://localhost:${port}/api-docs`);
                logger.info(`Status monitor: http://localhost:${port}/status`);
            });

            this.server.on('connection', (connection) => {
                this.connections.add(connection);
                connection.on('close', () => {
                    this.connections.delete(connection);
                });
            });

        } catch (error) {
            logger.error('Failed to start server:', error);
            process.exit(1);
        }
    }
}

if (cluster.isMaster && config.clustering.enabled) {
    const numWorkers = config.clustering.workers === 'auto' 
        ? os.cpus().length 
        : config.clustering.workers;

    logger.info(`Master ${process.pid} is running`);
    logger.info(`Starting ${numWorkers} workers`);

    for (let i = 0; i < numWorkers; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        logger.warn(`Worker ${worker.process.pid} died with code ${code} and signal ${signal}`);
        if (!worker.exitedAfterDisconnect) {
            logger.info('Starting a new worker');
            cluster.fork();
        }
    });

    cluster.on('online', (worker) => {
        logger.info(`Worker ${worker.process.pid} is online`);
    });

} else {
    const server = new EnterpriseServer();
    server.start().catch(error => {
        logger.error('Server startup failed:', error);
        process.exit(1);
    });
}

module.exports = EnterpriseServer;