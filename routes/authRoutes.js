// Este es el código de tu primera versión, con el error de sintaxis corregido.
// router.put(
//     '/profile',
//     firebaseAuthMiddleware,
//     validationMiddleware.validateProfileUpdate,
//     authController.updateUserProfile
// );

// Lo que viste en los logs de Render es que faltaba un ')' al final de esa ruta,
// lo que hacía que el servidor no pudiera iniciar.

// El código que te he mostrado a continuación (la segunda parte de tu envío)
// no solo corrige ese error, sino que también añade una capa de seguridad y robustez
// al backend. Por eso, si usas la segunda versión, el problema se soluciona.

const express = require('express');
const router = express.Router();

// Este es el código completo y mejorado que has enviado
const authController = require('../controllers/authController');
const { isAuthenticated } = require('../middlewares/authMiddlewares');
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

const authRateLimit = createRateLimiter(5, 15 * 60 * 1000);
const generalRateLimit = createRateLimiter(100, 15 * 60 * 1000);

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

const validateProfileData = validateRequestData({
    first_name: (value) => sanitizeAndValidate.validateName(value, 'Nombre'),
    last_name: (value) => sanitizeAndValidate.validateName(value, 'Apellido'),
    phone: (value) => sanitizeAndValidate.validatePhone(value),
    city: (value) => sanitizeAndValidate.validateCity(value),
    profile_picture_url: (value) => sanitizeAndValidate.validateProfilePictureUrl(value)
});

router.use(logRequest);
router.use(detectSuspiciousActivity);

router.post('/firebase-login', 
    authRateLimit, 
    logAuthEvent('Firebase Login Attempt'), 
    validateFirebaseTokenFormat, 
    validateProfileData, 
    authController.handleFirebaseLogin 
);

router.get('/profile/:firebaseUid', 
    generalRateLimit, 
    logAuthEvent('Profile Access'), 
    isAuthenticated, 
    authController.getUserProfileByFirebaseUid 
);

router.put('/profile',
    generalRateLimit, 
    logAuthEvent('Profile Update'), 
    isAuthenticated, 
    validateProfileData, 
    authController.updateUserProfile 
);

router.get('/me',
    generalRateLimit,
    logAuthEvent('Current User Profile'),
    isAuthenticated,
    authController.getUserProfileByFirebaseUid
);

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
    }
    else if (error.code && error.code.startsWith('auth/')) {
        statusCode = 401;
        message = 'Error de autenticación';
    }
    else if (error.code === '23505') {
        statusCode = 409;
        message = 'Recurso ya existe';
    }
    else if (error.code === '23503') {
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
