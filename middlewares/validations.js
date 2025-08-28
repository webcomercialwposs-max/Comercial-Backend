const validator = require('validator');
const responseHelper = require('../utils/responseHelper.js');

// Aquí puedes incluir tus funciones de validación granular como validateName, validatePhone, etc.
// Las mantendré igual que en tu código para no romper tu lógica existente.

const validateProfileUpdate = (req, res, next) => {
    const { first_name, last_name, phone, city, profile_picture_url } = req.body;
    const errors = {};

    try {
        // Validar cada campo opcional usando tus funciones de validación
        // Acepta `null` o `''` para campos opcionales
        const validatedFirstName = first_name !== undefined ? sanitizeAndValidate.validateName(first_name, 'First Name') : undefined;
        const validatedLastName = last_name !== undefined ? sanitizeAndValidate.validateName(last_name, 'Last Name') : undefined;
        const validatedPhone = phone !== undefined ? sanitizeAndValidate.validatePhone(phone) : undefined;
        const validatedCity = city !== undefined ? sanitizeAndValidate.validateCity(city) : undefined;
        const validatedPictureUrl = profile_picture_url !== undefined ? sanitizeAndValidate.validateProfilePictureUrl(profile_picture_url) : undefined;
        
        // Sobrescribe el cuerpo de la solicitud con los valores sanitizados
        req.body = {
            first_name: validatedFirstName,
            last_name: validatedLastName,
            phone: validatedPhone,
            city: validatedCity,
            profile_picture_url: validatedPictureUrl
        };
        
        // Si no hay errores, continúa con el siguiente middleware
        next();

    } catch (error) {
        // Captura los errores lanzados por tus funciones de validación
        // Y envía una respuesta de error 400
        errors[error.fieldName] = error.message; // Asume que tus funciones lanzan errores con fieldName
        return responseHelper.badRequest(res, 'Validation failed.', errors);
    }
};

// ... (El resto de tu código de validación) ...

const sanitizeAndValidate = {
    // Tus funciones de validación existentes:
    // validateName, validatePhone, validateCity, validateProfilePictureUrl
    validateName: (name, fieldName = 'Nombre') => {
        if (name === null || name === '') {
            return null;
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
    validateCity: (city) => {
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
    validateProfilePictureUrl: (url) => {
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


module.exports = {
  validateProfileUpdate,
};
