// routes/authRoutes.js - VERSIÓN MÍNIMA PARA DEBUG

const express = require('express');
const router = express.Router();

// Importar el controlador debug
const authController = require('../controllers/authController');

// Middleware simple de logging
const simpleLog = (req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    console.log('Headers:', req.headers);
    console.log('Body keys:', req.body ? Object.keys(req.body) : 'No body');
    next();
};

// RUTA MÍNIMA SIN MIDDLEWARES COMPLICADOS
router.post('/firebase-login', 
    simpleLog,                          // Solo logging básico
    authController.handleFirebaseLogin  // Controlador debug
);

// Ruta de prueba simple
router.get('/test', (req, res) => {
    res.json({
        message: 'Auth routes funcionando',
        timestamp: new Date().toISOString(),
        method: req.method,
        path: req.path
    });
});

module.exports = router;
