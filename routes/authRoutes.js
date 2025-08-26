const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { validateEmailQuery, validateRequestData, sanitizeAndValidate } = require('../middlewares/validation');

// Ruta para el registro de usuarios. Los logs mostrarán el flujo a través de los middlewares.
router.post(
  '/register',
  (req, res, next) => {
    // Log para confirmar que la ruta de registro ha sido alcanzada.
    console.log('LOG: Ruta POST /register alcanzada. Pasando a la validación de datos.');
    next();
  },
  validateRequestData({
    email: sanitizeAndValidate.validateEmail,
    password: sanitizeAndValidate.validatePassword,
    first_name: sanitizeAndValidate.validateName,
    last_name: sanitizeAndValidate.validateName,
    phone: sanitizeAndValidate.validatePhone,
    city: sanitizeAndValidate.validateCity,
  }),
  (req, res, next) => {
    // Log para ver los datos validados antes de pasarlos al controlador.
    console.log('LOG: La validación de datos para /register fue exitosa. Datos validados:', req.body);
    next();
  },
  authController.register
);

// Ruta para recuperar la contraseña. Aquí se encuentra el potencial punto de error original.
router.post(
  '/forgot-password',
  (req, res, next) => {
    // Log para confirmar que la ruta de "olvidé mi contraseña" ha sido alcanzada.
    console.log('LOG: Ruta POST /forgot-password alcanzada.');
    next();
  },
  (req, res, next) => {
    // Este middleware personalizado validará solo el email, que es el único dato necesario.
    console.log('LOG: Middleware de validación de email para /forgot-password iniciado.');
    try {
      // Usamos la función de validación importada para procesar el email del cuerpo de la solicitud.
      const validatedEmail = validateEmailQuery(req.body.email);
      req.body.email = validatedEmail;
      // Log para confirmar que el email fue validado y sanitizado correctamente.
      console.log('LOG: Email validado y sanitizado:', req.body.email);
      next();
    } catch (error) {
      // Si hay un error, lo registramos y enviamos una respuesta de error.
      console.error('ERROR: Falló la validación de email en el middleware. Detalle:', error.message);
      return res.status(400).json({ message: `Error de validación: ${error.message}` });
    }
  },
  (req, res, next) => {
    // Log para confirmar que el control se pasa al controlador.
    console.log('LOG: Pasando la solicitud a authController.forgotPassword.');
    next();
  },
  authController.forgotPassword
);

module.exports = router;
