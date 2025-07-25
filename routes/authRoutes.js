// Backend/routes/authRoutes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController'); // Asegúrate de que esta ruta sea correcta

// Ruta para obtener el perfil de usuario por Firebase UID (usado en login tradicional o para lectura)
// Esta ruta puede devolver 404 si el perfil no existe, lo cual es manejado en el frontend.
router.get('/profile/:firebaseUid', authController.getUserProfileByFirebaseUid);

// NUEVA RUTA UNIFICADA: Para manejar el login/registro de usuarios de Firebase (email/pass, Google, etc.)
// Este endpoint recibirá el ID Token de Firebase y gestionará la creación/actualización del perfil en la DB.
// Siempre devolverá 200 OK con el perfil del usuario (existente o recién creado).
router.post('/firebase-login', authController.handleFirebaseLogin);

module.exports = router;
