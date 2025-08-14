// D:\Pagina comercial\Backend\routes\userRoutes.js

const express = require('express');
const router = express.Router();

const userController = require('../controllers/userController');
console.log('Debug: Valor de userController:', userController);
console.log('Debug: Valor de userController.getUserProfile:', userController ? userController.getUserProfile : 'userController es null/undefined');


const { isAuthenticated } = require('../middlewares/authMiddlewares');
console.log('Debug: Valor de isAuthenticated:', isAuthenticated); // 🚨 ¡AÑADE ESTA LÍNEA!


// Todas las rutas definidas aquí requerirán que el usuario esté autenticado.

// Ruta para obtener el perfil completo del usuario autenticado
// GET /api/user/profile
router.get('/profile', isAuthenticated, userController.getUserProfile); // LÍNEA 18 ahora si contamos todos los logs

// Ruta para actualizar campos específicos del perfil del usuario autenticado
// PUT /api/user/profile
router.put('/profile', isAuthenticated, userController.updateUserProfile);

// Ruta para cambiar la contraseña del usuario autenticado (solo para email/password)
// PUT /api/user/change-password
router.put('/change-password', isAuthenticated, userController.changePassword);

module.exports = router;