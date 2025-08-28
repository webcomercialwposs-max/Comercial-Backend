// controllers/authController.js (VERSIÓN CORREGIDA)

const admin = require('firebase-admin');
const { pool } = require('../db/db.js');
const { securityLogger } = require('../middlewares/security.js');
const validator = require('validator');

// ... (El resto del código como PREPARED_QUERIES y secureUpsertUserProfile no necesita cambios y se mantiene igual)

/**
 * 🛠️ FUNCIONES DE VALIDACIÓN CORREGIDAS
 * Ahora permiten campos opcionales (null, '') sin lanzar un error.
 */
const sanitizeAndValidate = {
    validateName: (name, fieldName = 'Nombre') => {
        if (name === null || name === '') {
            return null; // Acepta valores nulos o vacíos
        }
        if (typeof name !== 'string') {
            throw new Error(`${fieldName} debe ser texto.`);
        }
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

    validatePhone: (phone) => {
        if (phone === null || phone === '') {
            return null; // Acepta valores nulos o vacíos
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

    validateCity: (city) => {
        if (city === null || city === '') {
            return null; // Acepta valores nulos o vacíos
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

    validateProfilePictureUrl: (url) => {
        if (url === null || url === '') {
            return null; // Acepta valores nulos o vacíos
        }
        if (typeof url !== 'string') {
            throw new Error('URL de imagen debe ser texto.');
        }
        const sanitized = url.trim();
        if (sanitized.length > 500) {
            throw new Error('URL de imagen no puede exceder 500 caracteres.');
        }
        if (!validator.isURL(sanitized, { protocols: ['http', 'https'], require_protocol: true, require_valid_protocol: true, allow_underscores: false, require_host: true, require_port: false, allow_trailing_dot: false, allow_protocol_relative_urls: false })) {
            throw new Error('Formato de URL de imagen no válido.');
        }
        const imageExtensions = /\.(jpg|jpeg|png|gif|webp|bmp)(\?.*)?$/i;
        if (!imageExtensions.test(sanitized)) {
            throw new Error('La URL debe ser una imagen válida (jpg, jpeg, png, gif, webp, bmp).');
        }
        return sanitized;
    }
};

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

const validateAndSanitizeAdditionalData = (rawData) => {
    if (!rawData || typeof rawData !== 'object') {
        return {};
    }
    const validatedData = {};
    try {
        if (rawData.first_name !== undefined) {
            validatedData.first_name = sanitizeAndValidate.validateName(rawData.first_name, 'Nombre');
        }
        if (rawData.last_name !== undefined) {
            validatedData.last_name = sanitizeAndValidate.validateName(rawData.last_name, 'Apellido');
        }
        if (rawData.phone !== undefined) {
            validatedData.phone = sanitizeAndValidate.validatePhone(rawData.phone);
        }
        if (rawData.city !== undefined) {
            validatedData.city = sanitizeAndValidate.validateCity(rawData.city);
        }
        if (rawData.profile_picture_url !== undefined) {
            validatedData.profile_picture_url = sanitizeAndValidate.validateProfilePictureUrl(rawData.profile_picture_url);
        }
        return validatedData;
    } catch (error) {
        console.error('🔴 ERROR en validateAndSanitizeAdditionalData:', error.message);
        securityLogger.warn('Data validation failed', { error: error.message, rawDataKeys: Object.keys(rawData) });
        throw new Error(`Datos inválidos: ${error.message}`);
    }
};

// ... (El resto del código para handleFirebaseLogin, getUserProfileByFirebaseUid y updateUserProfile no necesita cambios, ya que ahora las validaciones están en este mismo archivo).

module.exports = {
    handleFirebaseLogin,
    getUserProfileByFirebaseUid,
    updateUserProfile
};
