// D:\Backend\middlewares\authMiddleware.js
const jwt = require('jsonwebtoken');
// No necesitamos 'query' de db para el middleware de autenticación/autorización
// ya que la información del rol ya viene en el token después del login.
// const { query } = require('../db/db'); 

// Middleware para verificar el token JWT (Autenticación)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    // El token se envía típicamente en el formato: Authorization: Bearer <TOKEN>
    const token = authHeader && authHeader.split(' ')[1]; // Extrae el token después de 'Bearer'

    // Si no hay token, el usuario no está autenticado
    if (token == null) {
        return res.status(401).json({ message: 'Acceso denegado: Token no proporcionado.' });
    }

    // Asegúrate de que JWT_SECRET esté definido
    if (!process.env.JWT_SECRET) {
        console.error('Error: JWT_SECRET no está definido en las variables de entorno para el middleware.');
        return res.status(500).json({ message: 'Error interno del servidor: clave secreta JWT no configurada.' });
    }

    // Verificar el token
    // Usa la misma JWT_SECRET que usaste para firmar el token
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        // Si hay un error al verificar (ej. token inválido o expirado)
        if (err) {
            console.error('Error al verificar token:', err.message);
            return res.status(403).json({ message: 'Acceso denegado: Token inválido o expirado.' }); // 403 Forbidden
        }

        // Si el token es válido, adjuntamos la información del usuario al objeto 'req'
        // Esto permite que las rutas subsiguientes accedan a req.user (ej. req.user.user_id, req.user.role)
        req.user = user;
        next(); // Pasa al siguiente middleware o a la función de la ruta
    });
};

// Middleware para verificar el rol del usuario (Autorización)
// 'roles' es un array de roles permitidos (ej. ['Administrador', 'semillero'])
const authorizeRoles = (roles) => {
    return (req, res, next) => {
        // Asegúrate de que el middleware authenticateToken se haya ejecutado primero
        // para que req.user exista y contenga la información del rol del token.
        if (!req.user || !req.user.role) {
            return res.status(403).json({ message: 'Acceso denegado: Rol de usuario no disponible en el token.' });
        }

        // Si el rol del usuario (del token) NO está incluido en la lista de roles permitidos
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: `Acceso denegado: Se requiere uno de los siguientes roles: ${roles.join(', ')}.` });
        }

        next(); // Si el rol es permitido, pasa al siguiente middleware o a la función de la ruta
    };
};

module.exports = { authenticateToken, authorizeRoles };