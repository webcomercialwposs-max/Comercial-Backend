// middlewares/authMiddlewares.js
const jwt = require('jsonwebtoken');
const pool = require('../db/db.js').pool; // Ruta correcta para db.js

// Middleware para autenticar el token JWT
exports.authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: Bearer TOKEN

    if (token == null) {
        return res.status(401).json({ message: 'No autorizado: Token no proporcionado.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Error de verificación de token:', err.message);
            return res.status(403).json({ message: 'No autorizado: Token inválido o expirado.' });
        }
        // El 'user' decodificado del token contiene el user_id como 'id'
        req.user = user; // Guarda la información del usuario decodificada en la solicitud
        next();
    });
};

// Middleware para autorizar roles
exports.authorizeRoles = (requiredRoles) => {
    return async (req, res, next) => {
        if (!req.user || !req.user.role_name) {
            return res.status(403).json({ message: 'Acceso denegado: Rol de usuario no disponible.' });
        }

        const userRoleName = req.user.role_name;

        if (!requiredRoles.includes(userRoleName)) {
            return res.status(403).json({ message: `Acceso denegado: Se requiere uno de los siguientes roles: ${requiredRoles.join(', ')}.` });
        }
        next();
    };
};