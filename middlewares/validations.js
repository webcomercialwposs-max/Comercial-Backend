// middlewares/validations.js (versión corregida)

const validator = require('validator');

const sanitizeAndValidate = {
    /**
     * Validar nombres (first_name, last_name)
     * Ahora permite valores nulos o cadenas vacías sin lanzar un error.
     */
    validateName: (name, fieldName = 'Nombre') => {
        // ✅ ACEPTAR VALORES NULOS O VACÍOS como válidos si el campo es opcional.
        if (name === null || name === '') {
            return null; // Devuelve null para que la base de datos lo inserte como tal.
        }

        if (typeof name !== 'string') {
            throw new Error(`${fieldName} debe ser texto.`);
        }

        // Sanitizar y validar si el valor existe.
        const sanitized = name.trim().replace(/\s+/g, ' ');

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
     * Ahora permite valores nulos o cadenas vacías.
     */
    validatePhone: (phone) => {
        // ✅ ACEPTAR VALORES NULOS O VACÍOS
        if (phone === null || phone === '') {
            return null;
        }

        if (typeof phone !== 'string') {
            throw new Error('Teléfono debe ser texto.');
        }

        const sanitized = phone.trim().replace(/[^\d+\-\s()]/g, '');

        if (sanitized.length < 7) {
            throw new Error('Teléfono debe tener al menos 7 dígitos.');
        }

        if (sanitized.length > 20) {
            throw new Error('Teléfono no puede exceder 20 caracteres.');
        }

        const phoneRegex = /^[\+]?[\d\s\-\(\)]{7,20}$/;

        if (!phoneRegex.test(sanitized)) {
            throw new Error('Formato de teléfono no válido.');
        }

        return sanitized;
    },

    /**
     * Validar ciudad
     * Ahora permite valores nulos o cadenas vacías.
     */
    validateCity: (city) => {
        // ✅ ACEPTAR VALORES NULOS O VACÍOS
        if (city === null || city === '') {
            return null;
        }

        if (typeof city !== 'string') {
            throw new Error('Ciudad debe ser texto.');
        }

        const sanitized = city.trim().replace(/\s+/g, ' ');

        if (sanitized.length < 2) {
            throw new Error('Ciudad debe tener al menos 2 caracteres.');
        }

        if (sanitized.length > 100) {
            throw new Error('Ciudad no puede exceder 100 caracteres.');
        }

        const cityRegex = /^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄČĆĘÈÉÊËĖĮÌÍÎÏŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑÇČŠŽ\s\-'\.]+$/;

        if (!cityRegex.test(sanitized)) {
            throw new Error('Ciudad contiene caracteres no válidos.');
        }

        return sanitized;
    },

    /**
     * Validar URL de imagen de perfil
     * Ahora permite valores nulos o cadenas vacías.
     */
    validateProfilePictureUrl: (url) => {
        // ✅ ACEPTAR VALORES NULOS O VACÍOS
        if (url === null || url === '') {
            return null;
        }

        if (typeof url !== 'string') {
            throw new Error('URL de imagen debe ser texto.');
        }
        
        const sanitized = url.trim();

        if (sanitized.length > 500) {
            throw new Error('URL de imagen no puede exceder 500 caracteres.');
        }

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

        const imageExtensions = /\.(jpg|jpeg|png|gif|webp|bmp)(\?.*)?$/i;
        if (!imageExtensions.test(sanitized)) {
            throw new Error('La URL debe ser una imagen válida (jpg, jpeg, png, gif, webp, bmp).');
        }

        return sanitized;
    }
};

// ... El resto del código permanece igual ...

module.exports = {
    sanitizeAndValidate,
    validateEmailQuery,
    validateUserProfileData,
    validateRequestData,
    validateRequestDataStrict,
    getClientIp
};
