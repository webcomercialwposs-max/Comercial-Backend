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

// 🔧 Importar la función correcta del controlador para la validación
const {
    validateRequestData
} = require('../middlewares/validations');

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
        return res.status(401).json({
            message: 'Formato de autorización inválido.'
        });
    }
    
    const token = authHeader.split(' ')[1];
    if (!token || token.length < 50) {
        securityLogger.warn('Invalid Firebase token format', {
            ip: req.ip,
            tokenLength: token ? token.length : 0
        });
        return res.status(401).json({
            message: 'Token de autenticación inválido.'
        });
    }
    
    next();
};

/**
 * 🔧 MIDDLEWARE CORREGIDO: Validar datos de perfil de usuario
 */
const validateProfileData = (req, res, next) => {
    try {
        if (req.body && Object.keys(req.body).length > 0) {
            // ✅ CORREGIDO: Usar la función correcta del controlador
            const validatedData = authController.validateAndSanitizeAdditionalData(req.body);
            req.body = validatedData;
        }
        next();
    } catch (error) {
        return res.status(400).json({
            success: false,
            message: error.message
        });
    }
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
    validateRequestData,
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
    validateRequestData,
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
    validateRequestData,
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
    validateRequestData,
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

    if (error.message && error.message.includes('Errores de validación:')) {
        statusCode = 400;
        message = error.message;
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
