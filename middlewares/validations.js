const validator = require('validator');

/**
 * Funciones de sanitización y validación de datos
 */
const sanitizeAndValidate = {
    /**
     * Validar nombres (first_name, last_name)
     */
    validateName: (name, fieldName = 'Nombre') => {
        // Log al inicio de la función
        console.log(`LOG: Iniciando validación de ${fieldName} con el valor:`, name);
        if (!name || typeof name !== 'string') {
            console.error(`ERROR: ${fieldName} no es un string. Valor recibido:`, name);
            throw new Error(`${fieldName} es requerido y debe ser texto.`);
        }
        
        // Sanitizar: trim y normalizar espacios
        const sanitized = name.trim().replace(/\s+/g, ' ');
        console.log(`LOG: ${fieldName} sanitizado:`, sanitized);
        
        // Validaciones
        if (sanitized.length < 2) {
            console.error(`ERROR: ${fieldName} tiene menos de 2 caracteres.`);
            throw new Error(`${fieldName} debe tener al menos 2 caracteres.`);
        }
        
        if (sanitized.length > 50) {
            console.error(`ERROR: ${fieldName} excede los 50 caracteres.`);
            throw new Error(`${fieldName} no puede exceder 50 caracteres.`);
        }
        
        const nameRegex = /^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄČĆĘÈÉÊËĖĮÌÍÎÏŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑÇČŠŽ\s\-'\.]+$/;
        
        if (!nameRegex.test(sanitized)) {
            console.error(`ERROR: ${fieldName} contiene caracteres no válidos.`);
            throw new Error(`${fieldName} contiene caracteres no válidos.`);
        }
        
        console.log(`LOG: ${fieldName} validado exitosamente.`);
        return sanitized;
    },

    // ... (el resto de las funciones de validación)

    /**
     * Validar URL de imagen de perfil
     */
    validateProfilePictureUrl: (url) => {
        // Log al inicio de la función
        console.log('LOG: Iniciando validación de URL de imagen con el valor:', url);
        if (!url || typeof url !== 'string') {
            console.error('ERROR: URL de imagen no es un string.');
            throw new Error('URL de imagen es requerida y debe ser texto.');
        }
        
        const sanitized = url.trim();
        console.log('LOG: URL sanitizada:', sanitized);
        
        if (sanitized.length > 500) {
            console.error('ERROR: URL de imagen excede los 500 caracteres.');
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
            // Log de error específico
            console.error('ERROR: Formato de URL de imagen no válido. Valor:', sanitized);
            throw new Error('Formato de URL de imagen no válido.');
        }
        
        // Verificar extensiones de imagen permitidas
        const imageExtensions = /\.(jpg|jpeg|png|gif|webp|bmp)(\?.*)?$/i;
        
        if (!imageExtensions.test(sanitized)) {
            // Log de error específico
            console.error('ERROR: Extensión de imagen no válida.');
            throw new Error('La URL debe ser una imagen válida (jpg, jpeg, png, gif, webp, bmp).');
        }
        
        console.log('LOG: URL de imagen validada exitosamente.');
        return sanitized;
    }
};

/**
 * Validar email con sanitización
 */
const validateEmailQuery = (email) => {
    // Log al inicio de la función
    console.log('LOG: validateEmailQuery: Iniciando validación para el email:', email);
    if (!email || typeof email !== 'string') {
        // Si el valor no es un string, lo registramos para saber qué está pasando.
        console.error('ERROR: validateEmailQuery: El email no es un string o es nulo. Tipo de dato recibido:', typeof email);
        throw new Error('Email es requerido y debe ser texto.');
    }
    
    const sanitized = email.trim().toLowerCase();
    // Log para ver el valor después de la sanitización.
    console.log('LOG: validateEmailQuery: Email sanitizado:', sanitized);
    
    if (!validator.isEmail(sanitized)) {
        // Log de error de formato.
        console.error('ERROR: validateEmailQuery: Formato de email no válido. Valor:', sanitized);
        throw new Error('Formato de email no válido.');
    }
    
    if (sanitized.length > 254) {
        // Log de error de longitud.
        console.error('ERROR: validateEmailQuery: Email excede 254 caracteres. Longitud:', sanitized.length);
        throw new Error('Email no puede exceder 254 caracteres.');
    }
    
    console.log('LOG: validateEmailQuery: Validación exitosa.');
    return sanitized;
};

// ... (el resto de las funciones de validación)

module.exports = {
    sanitizeAndValidate,
    validateEmailQuery,
    validateUserProfileData,
    validateRequestData
};
