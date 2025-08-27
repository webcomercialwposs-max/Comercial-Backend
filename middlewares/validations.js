const validator = require('validator');

/**
 * Funciones de sanitización y validación de datos
 */
const sanitizeAndValidate = {
    /**
     * Validar nombres (first_name, last_name)
     */
    validateName: (name, fieldName = 'Nombre') => {
        if (!name || typeof name !== 'string') {
            throw new Error(`${fieldName} es requerido y debe ser texto.`);
        }
        
        // Sanitizar: trim y normalizar espacios
        const sanitized = name.trim().replace(/\s+/g, ' ');
        
        // Validaciones
        if (sanitized.length < 2) {
            throw new Error(`${fieldName} debe tener al menos 2 caracteres.`);
        }
        
        if (sanitized.length > 50) {
            throw new Error(`${fieldName} no puede exceder 50 caracteres.`);
        }
        
        const nameRegex = /^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄČĆĘÈÉÊËĖĮÌÍÎÏŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑÇČŠŽ\s\-'\.]+$/;
        
        if (!nameRegex.test(sanitized)) {
            throw new Error(`${fieldName} contiene caracteres no válidos.`);
        }
        
        return sanitized;
    },

    /**
     * Validar teléfono
     */
    validatePhone: (phone) => {
        if (!phone || typeof phone !== 'string') {
            throw new Error('Teléfono es requerido y debe ser texto.');
        }
        
        // Sanitizar: remover espacios y caracteres especiales excepto + y -
        const sanitized = phone.trim().replace(/[^\d+\-\s()]/g, '');
        
        if (sanitized.length < 7) {
            throw new Error('Teléfono debe tener al menos 7 dígitos.');
        }
        
        if (sanitized.length > 20) {
            throw new Error('Teléfono no puede exceder 20 caracteres.');
        }
        
        // Validar formato básico de teléfono
        const phoneRegex = /^[\+]?[\d\s\-\(\)]{7,20}$/;
        
        if (!phoneRegex.test(sanitized)) {
            throw new Error('Formato de teléfono no válido.');
        }
        
        return sanitized;
    },

    /**
     * Validar ciudad
     */
    validateCity: (city) => {
        if (!city || typeof city !== 'string') {
            throw new Error('Ciudad es requerida y debe ser texto.');
        }
        
        // Sanitizar: trim y normalizar espacios
        const sanitized = city.trim().replace(/\s+/g, ' ');
        
        if (sanitized.length < 2) {
            throw new Error('Ciudad debe tener al menos 2 caracteres.');
        }
        
        if (sanitized.length > 100) {
            throw new Error('Ciudad no puede exceder 100 caracteres.');
        }
        
        // Permitir letras, espacios, guiones y apostrofes
        const cityRegex = /^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄČĆĘÈÉÊËĖĮÌÍÎÏŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑÇČŠŽ\s\-'\.]+$/;
        
        if (!cityRegex.test(sanitized)) {
            throw new Error('Ciudad contiene caracteres no válidos.');
        }
        
        return sanitized;
    },

    /**
     * Validar URL de imagen de perfil
     */
    validateProfilePictureUrl: (url) => {
        if (!url || typeof url !== 'string') {
            throw new Error('URL de imagen es requerida y debe ser texto.');
        }
        
        const sanitized = url.trim();
        
        if (sanitized.length > 500) {
            throw new Error('URL de imagen no puede exceder 500 caracteres.');
        }
        
        // Validar formato de URL
        if (!validator.isURL(sanitized, {
            protocols: ['http', 'https'],
            require_protocol: true,
            require_valid_protocol: true,
            allow_underscores: false,
            require_host: true,
            require_port: false,
            allow_trailing_dot: false,
            allow_protocol_relative_urls: false
        })) {
            throw new Error('Formato de URL de imagen no válido.');
        }
        
        // Verificar extensiones de imagen permitidas
        const imageExtensions = /\.(jpg|jpeg|png|gif|webp|bmp)(\?.*)?$/i;
        
        if (!imageExtensions.test(sanitized)) {
            throw new Error('La URL debe ser una imagen válida (jpg, jpeg, png, gif, webp, bmp).');
        }
        
        return sanitized;
    }
};

/**
 * Validar email con sanitización
 */
const validateEmailQuery = (email) => {
    if (!email || typeof email !== 'string') {
        throw new Error('Email es requerido y debe ser texto.');
    }
    
    const sanitized = email.trim().toLowerCase();
    
    if (!validator.isEmail(sanitized)) {
        throw new Error('Formato de email no válido.');
    }
    
    if (sanitized.length > 254) {
        throw new Error('Email no puede exceder 254 caracteres.');
    }
    
    return sanitized;
};

/**
 * Validar datos completos de perfil de usuario
 */
const validateUserProfileData = (data) => {
    const validatedData = {};
    
    if (data.first_name !== undefined) {
        validatedData.first_name = sanitizeAndValidate.validateName(data.first_name, 'Nombre');
    }
    
    if (data.last_name !== undefined) {
        validatedData.last_name = sanitizeAndValidate.validateName(data.last_name, 'Apellido');
    }
    
    if (data.phone !== undefined) {
        validatedData.phone = sanitizeAndValidate.validatePhone(data.phone);
    }
    
    if (data.city !== undefined) {
        validatedData.city = sanitizeAndValidate.validateCity(data.city);
    }
    
    if (data.profile_picture_url !== undefined) {
        validatedData.profile_picture_url = sanitizeAndValidate.validateProfilePictureUrl(data.profile_picture_url);
    }
    
    if (data.email !== undefined) {
        validatedData.email = validateEmailQuery(data.email);
    }
    
    return validatedData;
};

/**
 * 🔧 FUNCIÓN CORREGIDA: Obtener IP del cliente de forma segura
 * Revisa los encabezados que envían los proxies como Render.
 */
const getClientIp = (req) => {
    // Protección contra 'req' no definido
    if (!req) {
        return 'unknown';
    }

    // Intentar obtener IP de diferentes fuentes
    let ip = null;
    
    // Headers de proxy/load balancer (más confiables)
    if (req.headers) {
        ip = req.headers['cf-connecting-ip'] ||          // Cloudflare
             req.headers['x-real-ip'] ||                 // Nginx
             req.headers['x-forwarded-for'] ||           // Standard proxy header
             req.headers['x-client-ip'] ||               // Apache
             req.headers['x-cluster-client-ip'];         // Cluster
    }
    
    // Si viene de x-forwarded-for, tomar solo la primera IP (la del cliente original)
    if (ip && ip.includes(',')) {
        ip = ip.split(',')[0].trim();
    }
    
    // Fallback a propiedades de socket (menos confiables en producción)
    if (!ip) {
        ip = req.socket?.remoteAddress ||
             req.ip ||
             (req.connection && req.connection.remoteAddress) ||
             'unknown';
    }
    
    // Limpiar IPv6 localhost
    if (ip === '::1' || ip === '::ffff:127.0.0.1') {
        ip = '127.0.0.1';
    }
    
    return ip || 'unknown';
};

/**
 * 🔧 MIDDLEWARE CORREGIDO: Validar datos de request básicos.
 */
const validateRequestData = (req, res, next) => {
    try {
        // Verificar que res existe (esto debe resolver tu error)
        if (!res || typeof res.status !== 'function') {
            console.error('ERROR: Objeto res no disponible o inválido en validateRequestData');
            throw new Error('Error interno del servidor');
        }

        // Validaciones básicas de request
        if (!req || typeof req !== 'object') {
            throw new Error('Request inválido.');
        }
        
        // ✅ CORRECCIÓN: Obtener IP pero no fallar si no está disponible
        const clientIp = getClientIp(req);
        
        // Solo registrar en log si no se pudo obtener IP, pero no fallar la request
        if (!clientIp || clientIp === 'unknown') {
            console.warn('⚠️ No se pudo determinar la IP del cliente');
        }
        
        // Validar User-Agent si existe (hacer más permisivo)
        const userAgent = req.get && req.get('User-Agent');
        if (userAgent && userAgent.length > 1000) { // Aumentamos el límite
            console.warn('⚠️ User-Agent muy largo, truncando...');
        }

        // Almacenar la IP en el request para uso posterior
        req.clientIp = clientIp;

        // Si todo es válido, continuar al siguiente middleware o ruta
        next();

    } catch (error) {
        // Verificar que res sigue siendo válido antes de enviar respuesta
        if (res && typeof res.status === 'function') {
            return res.status(400).json({
                success: false,
                message: error.message || 'Error de validación'
            });
        } else {
            // Si res no es válido, logear el error y no enviar respuesta
            console.error('ERROR CRÍTICO: No se puede enviar respuesta de error:', error.message);
        }
    }
};

/**
 * 🆕 MIDDLEWARE OPCIONAL: Versión más estricta para rutas que requieren IP válida
 */
const validateRequestDataStrict = (req, res, next) => {
    try {
        if (!res || typeof res.status !== 'function') {
            console.error('ERROR: Objeto res no disponible en validateRequestDataStrict');
            throw new Error('Error interno del servidor');
        }

        if (!req || typeof req !== 'object') {
            throw new Error('Request inválido.');
        }
        
        const clientIp = getClientIp(req);
        
        // En modo estricto, sí requerimos una IP válida
        if (!clientIp || clientIp === 'unknown') {
            throw new Error('No se pudo determinar la IP del cliente.');
        }
        
        req.clientIp = clientIp;
        next();

    } catch (error) {
        if (res && typeof res.status === 'function') {
            return res.status(400).json({
                success: false,
                message: error.message
            });
        } else {
            console.error('ERROR CRÍTICO en validateRequestDataStrict:', error.message);
        }
    }
};

module.exports = {
    sanitizeAndValidate,
    validateEmailQuery,
    validateUserProfileData,
    validateRequestData,
    validateRequestDataStrict,  // Nueva función más estricta
    getClientIp                 // Exportar por si la necesitas en otros lugares
};
