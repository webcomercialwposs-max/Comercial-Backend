// routes/authRoutes.js
const express = require('express');
const authController = require('../controllers/authController');
// const authMiddleware = require('../middleware/authMiddleware'); // Comentado si no lo estás usando aún

const router = express.Router();

// Ruta para registrar un nuevo usuario y su perfil
router.post('/register', authController.registerUser);

// Ruta para iniciar sesión
router.post('/login', authController.loginUser);

// Ruta para obtener el perfil del usuario (ejemplo, podría requerir autenticación JWT)
// router.get('/profile', authMiddleware.authenticateToken, authController.getUserProfile); // Si usas middleware
router.get('/profile', authController.getUserProfile); // Sin middleware de autenticación por ahora

module.exports = router;