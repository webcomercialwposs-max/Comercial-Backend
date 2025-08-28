// authRoutes.js - VERSIÓN CORREGIDA Y FUNCIONAL

const express = require('express');
const router = express.Router();

// Importar los controladores
const authController = require('../controllers/authController');

// Importar middlewares existentes
const { isAuthenticated } = require('../middlewares/authMiddlewares');

// Importar middlewares de seguridad
const {
    securityLogger,
    logRequest,
    detectSuspiciousActivity,
    createRateLimiter
} = require('../middlewares/security');

// =============================================
// CONFIGURAR RATE LIMITERS ESPECÍFICOS
// =============================================

// Rate limiter estricto para autenticación (5 intentos por 15 min)
const authRateLimit = createRateLimiter(5, 15 * 60 * 1000);

// Rate limiter general para otras rutas (100 intentos por 15 min)
const generalRateLimit = createRateLimiter(100, 15 * 60 * 1000);

// =============================================
// MIDDLEWARES PERSONALIZADOS PARA AUTH
// =============================================

/**
 * Middleware para logging específico de eventos de auth
 */
const logAuthEvent = (eventType) => {
    return (req, res, next) => {
        securityLogger.info(`Auth event: ${eventType}`, {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            url: req.originalUrl,
            method: req.method,
            hasAuthHeader: !!req.headers.authorization
        });
        next();
    };
};

/**
 * Middleware para validar formato básico de token Firebase antes del procesamiento
 */
const validateFirebaseTokenFormat = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        securityLogger.warn('Invalid auth header format', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            authHeader: authHeader ? 'present' : 'missing'
        });
        return res.status(400).json({
            message: 'Solicitud inválida detectada.'
        });
    }
    
    const token = authHeader.split(' ')[1];
    if (!token || token.length < 50) {
        securityLogger.warn('Invalid Firebase token format', {
            ip: req.ip,
            tokenLength: token ? token.length : 0
        });
        return res.status(400).json({
            message: 'Solicitud inválida detectada.'
        });
    }
    
    next();
};

/**
 * Middleware para validar datos de perfil de usuario (CORREGIDO)
 */
const validateProfileData = (req, res, next) => {
    try {
        // Permitir body vacío o undefined
        if (!req.body || Object.keys(req.body).length === 0) {
            req.body = {};
            return next();
        }

        // Usar la función del controlador para validar datos adicionales
        const validatedData = authController.validateAndSanitizeAdditionalData(req.body);
        req.body = validatedData;
        next();
    } catch (error) {
        securityLogger.warn('Profile data validation failed', {
            error: error.message,
            ip: req.ip,
            bodyKeys: req.body ? Object.keys(req.body) : []
        });
        
        return res.status(400).json({
            message: 'Solicitud inválida detectada.'
        });
    }
};

/**
 * Middleware básico de validación de request (SIMPLIFICADO)
 */
const basicRequestValidation = (req, res, next) => {
    // Validaciones básicas de seguridad
    const userAgent = req.get('User-Agent');
    const contentType = req.get('Content-Type');
    
    // Validar User-Agent
    if (!userAgent || userAgent.length > 1000) {
        securityLogger.warn('Invalid or suspicious User-Agent', {
            ip: req.ip,
            userAgent: userAgent ? userAgent.substring(0, 100) + '...' : 'missing'
        });
        return res.status(400).json({
            message: 'Solicitud inválida detectada.'
        });
    }
    
    // Para POST/PUT, validar Content-Type si hay body
    if ((req.method === 'POST' || req.method === 'PUT') && req.body && Object.keys(req.body).length > 0) {
        if (!contentType || !contentType.includes('application/json')) {
            securityLogger.warn('Invalid Content-Type for request with body', {
                ip: req.ip,
                method: req.method,
                contentType: contentType || 'missing'
            });
            return res.status(400).json({
                message: 'Solicitud inválida detectada.'
            });
        }
    }
    
    next();
};

// =============================================
// APLICAR MIDDLEWARES GLOBALES PARA AUTH
// =============================================

router.use(logRequest);
router.use(detectSuspiciousActivity);

// =============================================
// RUTAS DE AUTENTICACIÓN
// =============================================

/**
 * @route POST /api/auth/firebase-login
 * @description Ruta unificada de login y registro con Firebase
 */
router.post('/firebase-login',
    authRateLimit,
    logAuthEvent('Firebase Login Attempt'),
    basicRequestValidation,
    validateFirebaseTokenFormat,
    validateProfileData,
    authController.handleFirebaseLogin
);

/**
 * @route GET /api/auth/profile/:firebaseUid
 * @description Obtener perfil de usuario por Firebase UID
 */
router.get('/profile/:firebaseUid',
    generalRateLimit,
    logAuthEvent('Profile Access'),
    basicRequestValidation,
    isAuthenticated,
    authController.getUserProfileByFirebaseUid
);

/**
 * @route PUT /api/auth/profile
 * @description Actualizar perfil de usuario autenticado
 */
router.put('/profile',
    generalRateLimit,
    logAuthEvent('Profile Update'),
    basicRequestValidation,
    isAuthenticated,
    validateProfileData,
    authController.updateUserProfile
);

/**
 * @route GET /api/auth/me
 * @description Obtener perfil del usuario autenticado actual
 */
router.get('/me',
    generalRateLimit,
    logAuthEvent('Current User Profile'),
    basicRequestValidation,
    isAuthenticated,
    authController.getUserProfileByFirebaseUid
);

// =============================================
// MANEJO DE ERRORES ESPECÍFICO PARA AUTH
// =============================================

router.use((error, req, res, next) => {
    securityLogger.error('Auth route error', {
        error: error.message,
        code: error.code,
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.userId || 'anonymous',
        timestamp: new Date().toISOString()
    });

    let statusCode = 500;
    let message = 'Error interno del servidor';

    if (error.message && error.message.includes('Datos inválidos:')) {
        statusCode = 400;
        message = 'Solicitud inválida detectada.';
    } else if (error.code && error.code.startsWith('auth/')) {
        statusCode = 401;
        message = 'Error de autenticación';
    } else if (error.code === '23505') {
        statusCode = 409;
        message = 'Recurso ya existe';
    } else if (error.code === '23503') {
        statusCode = 400;
        message = 'Error de referencia de datos';
    }

    if (process.env.NODE_ENV === 'production') {
        res.status(statusCode).json({
            message: message,
            requestId: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
        });
    } else {
        res.status(statusCode).json({
            message: message,
            error: error.message,
            path: req.path,
            timestamp: new Date().toISOString()
        });
    }
});

module.exports = router;
