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
 * Validar datos de request básicos
 */
const validateRequestData = (req) => {
    // Validaciones básicas de request
    if (!req || typeof req !== 'object') {
        throw new Error('Request inválido.');
    }
    
    // Validar IP
    if (!req.ip || typeof req.ip !== 'string') {
        throw new Error('IP del cliente no válida.');
    }
    
    // Validar User-Agent si existe
    if (req.get && req.get('User-Agent') && req.get('User-Agent').length > 500) {
        throw new Error('User-Agent demasiado largo.');
    }
    
    return true;
};

module.exports = {
    sanitizeAndValidate,
    validateEmailQuery,
    validateUserProfileData,
    validateRequestData
};
