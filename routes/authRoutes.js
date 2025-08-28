// D:\Pagina comercial\Backend\routes\authRoutes.js - VERSIÓN CORREGIDA

const express = require('express');
const router = express.Router();

// Importar los controladores
const authController = require('../controllers/authController');

// Importar middlewares existentes
const { isAuthenticated } = require('../middlewares/authMiddlewares'); 

// Importar middlewares de seguridad (ajustados a lo que realmente tienes)
const { 
    securityLogger, 
    logRequest, 
    detectSuspiciousActivity, 
    createRateLimiter 
} = require('../middlewares/security');

const { 
    validateUserProfileData,
    validateRequestData,
    sanitizeAndValidate 
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
    if (!token || token.length < 50) { // Tokens Firebase son largos
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
 * Middleware para validar datos de perfil de usuario
 */
const validateProfileData = validateRequestData({
    first_name: (value) => sanitizeAndValidate.validateName(value, 'Nombre'),
    last_name: (value) => sanitizeAndValidate.validateName(value, 'Apellido'),
    phone: (value) => sanitizeAndValidate.validatePhone(value),
    city: (value) => sanitizeAndValidate.validateCity(value),
    profile_picture_url: (value) => sanitizeAndValidate.validateProfilePictureUrl(value)
});

// =============================================
// APLICAR MIDDLEWARES GLOBALES PARA AUTH
// =============================================

// Logging de todas las requests
router.use(logRequest);

// Detectar actividad sospechosa
router.use(detectSuspiciousActivity);

// =============================================
// RUTAS DE AUTENTICACIÓN
// =============================================

/**
 * @route POST /api/auth/firebase-login
 * @description Ruta unificada de login y registro con Firebase
 * @access Public
 * 
 * PROTECCIONES APLICADAS:
 * ✅ Rate limiting estricto (5 intentos por 15 min)
 * ✅ Logging de eventos de seguridad
 * ✅ Validación básica de formato de token
 * ✅ Validación y sanitización de datos adicionales
 * ✅ Detección de actividad sospechosa
 */
router.post('/firebase-login', 
    authRateLimit,                      // 🛡️ Límite estricto para login
    logAuthEvent('Firebase Login Attempt'), // 📝 Log del intento
    validateFirebaseTokenFormat,        // 🔐 Validación básica de token
    validateProfileData,                // ✅ Validar datos adicionales opcionales
    authController.handleFirebaseLogin  // 🎯 Controlador principal
);

/**
 * @route GET /api/auth/profile/:firebaseUid
 * @description Obtener perfil de usuario por Firebase UID
 * @access Private (requiere autenticación)
 * 
 * PROTECCIONES APLICADAS:
 * ✅ Rate limiting general
 * ✅ Autenticación requerida
 * ✅ Logging de accesos al perfil
 */
router.get('/profile/:firebaseUid', 
    generalRateLimit,                   // 🛡️ Límite general
    logAuthEvent('Profile Access'),     // 📝 Log de acceso
    isAuthenticated,                    // 🔐 Autenticación requerida
    authController.getUserProfileByFirebaseUid // 🎯 Controlador
);

/**
 * @route PUT /api/auth/profile
 * @description Actualizar perfil de usuario autenticado
 * @access Private (requiere autenticación)
 * 
 * PROTECCIONES APLICADAS:
 * ✅ Rate limiting general
 * ✅ Autenticación requerida
 * ✅ Validación de datos de entrada
 * ✅ Logging de modificaciones
 */
router.put('/profile',
    generalRateLimit,                   // 🛡️ Límite general
    logAuthEvent('Profile Update'),     // 📝 Log de modificación
    isAuthenticated,                    // 🔐 Autenticación requerida
    validateProfileData,                // ✅ Validar datos de entrada
    authController.updateUserProfile    // 🎯 Controlador
);

/**
 * @route GET /api/auth/me
 * @description Obtener perfil del usuario autenticado actual
 * @access Private (requiere autenticación)
 */
router.get('/me',
    generalRateLimit,
    logAuthEvent('Current User Profile'),
    isAuthenticated,
    authController.getUserProfileByFirebaseUid
);

// =============================================
// MANEJO DE ERRORES ESPECÍFICO PARA AUTH
// =============================================

/**
 * Middleware de manejo de errores para rutas de autenticación
 * Evita exponer información sensible
 */
router.use((error, req, res, next) => {
    // Log del error de forma segura
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

    // Determinar el código de estado
    let statusCode = 500;
    let message = 'Error interno del servidor';

    // Errores conocidos de validación
    if (error.message && error.message.includes('Errores de validación:')) {
        statusCode = 400;
        message = error.message;
    }
    // Errores de Firebase
    else if (error.code && error.code.startsWith('auth/')) {
        statusCode = 401;
        message = 'Error de autenticación';
    }
    // Errores de base de datos
    else if (error.code === '23505') {
        statusCode = 409;
        message = 'Recurso ya existe';
    }
    else if (error.code === '23503') {
        statusCode = 400;
        message = 'Error de referencia de datos';
    }

    // Respuesta según el entorno
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
