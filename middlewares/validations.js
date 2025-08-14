// middlewares/validation.js
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
        
        // Solo letras, espacios, acentos y algunos caracteres especiales
        const nameRegex = /^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄČĆĘÈÉÊËĖĮÌÍÎÏŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑÇČŠŽ\s\-'\.]+$/;
        
        if (!nameRegex.test(sanitized)) {
            throw new Error(`${fieldName} contiene caracteres no válidos.`);
        }
        
        return sanitized;
    },

    /**
     * Validar número de teléfono
     */
    validatePhone: (phone) => {
        if (!phone || typeof phone !== 'string') {
            throw new Error('Teléfono es requerido y debe ser texto.');
        }
        
        // Sanitizar: remover espacios y caracteres no numéricos excepto + y -
        const sanitized = phone.trim().replace(/[^\d\+\-\s\(\)]/g, '');
        
        if (sanitized.length < 7) {
            throw new Error('Número de teléfono debe tener al menos 7 dígitos.');
        }
        
        if (sanitized.length > 20) {
            throw new Error('Número de teléfono no puede exceder 20 caracteres.');
        }
        
        // Validar formato básico (números, espacios, +, -, paréntesis)
        const phoneRegex = /^[\d\+\-\s\(\)]+$/;
        
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
        
        // Sanitizar
        const sanitized = city.trim().replace(/\s+/g, ' ');
        
        if (sanitized.length < 2) {
            throw new Error('Ciudad debe tener al menos 2 caracteres.');
        }
        
        if (sanitized.length > 100) {
            throw new Error('Ciudad no puede exceder 100 caracteres.');
        }
        
        // Letras, espacios, acentos, guiones
        const cityRegex = /^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄČĆĘÈÉÊËĖĮÌÍÎÏŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑÇČŠŽ\s\-\.]+$/;
        
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
    const errors = [];
    const validatedData = {};
    
    try {
        if (data.first_name !== undefined) {
            validatedData.first_name = sanitizeAndValidate.validateName(data.first_name, 'Nombre');
        }
    } catch (error) {
        errors.push(error.message);
    }
    
    try {
        if (data.last_name !== undefined) {
            validatedData.last_name = sanitizeAndValidate.validateName(data.last_name, 'Apellido');
        }
    } catch (error) {
        errors.push(error.message);
    }
    
    try {
        if (data.phone !== undefined) {
            validatedData.phone = sanitizeAndValidate.validatePhone(data.phone);
        }
    } catch (error) {
        errors.push(error.message);
    }
    
    try {
        if (data.city !== undefined) {
            validatedData.city = sanitizeAndValidate.validateCity(data.city);
        }
    } catch (error) {
        errors.push(error.message);
    }
    
    try {
        if (data.profile_picture_url !== undefined) {
            validatedData.profile_picture_url = sanitizeAndValidate.validateProfilePictureUrl(data.profile_picture_url);
        }
    } catch (error) {
        errors.push(error.message);
    }
    
    try {
        if (data.email !== undefined) {
            validatedData.email = validateEmailQuery(data.email);
        }
    } catch (error) {
        errors.push(error.message);
    }
    
    if (errors.length > 0) {
        throw new Error(`Errores de validación: ${errors.join(', ')}`);
    }
    
    return validatedData;
};

/**
 * Middleware para validar datos de entrada en requests
 */
const validateRequestData = (validationRules) => {
    return (req, res, next) => {
        try {
            const validatedData = {};
            
            for (const [field, validator] of Object.entries(validationRules)) {
                if (req.body[field] !== undefined) {
                    validatedData[field] = validator(req.body[field]);
                }
            }
            
            // Reemplazar req.body con datos validados
            req.body = { ...req.body, ...validatedData };
            next();
            
        } catch (error) {
            return res.status(400).json({
                message: `Error de validación: ${error.message}`
            });
        }
    };
};

module.exports = {
    sanitizeAndValidate,
    validateEmailQuery,
    validateUserProfileData,
    validateRequestData
};