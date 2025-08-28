const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController.js');
const firebaseAuthMiddleware = require('../middlewares/firebaseAuth.js');
const validationMiddleware = require('../middlewares/validation.js');

// Endpoint para el login/sincronización. No necesita token de auth en el header.
router.post('/login', authController.firebaseLogin);

// Endpoints protegidos. El middleware firebaseAuthMiddleware asegura que el token sea válido.
router.get('/profile', firebaseAuthMiddleware, authController.getUserProfile);
router.put(
  '/profile',
  firebaseAuthMiddleware,
  validationMiddleware.validateProfileUpdate, // Middleware de validación para el body
  authController.updateUserProfile
);

// Endpoint para verificar el estado de la sesión, solo necesita el middleware de auth.
router.get('/status', firebaseAuthMiddleware, authController.getAuthStatus);

module.exports = router;
