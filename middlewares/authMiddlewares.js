// D:\Pagina comercial\Backend\middlewares\authMiddlewares.js
const admin = require('firebase-admin');
const { pool } = require('../db/db.js');

/**
 * @description Middleware para verificar el ID Token de Firebase y adjuntar los datos del usuario a la solicitud.
 * Este middleware realiza las siguientes acciones:
 * 1. Extrae el token del encabezado 'Authorization'.
 * 2. Valida el token usando Firebase Admin SDK.
 * 3. Busca el perfil completo del usuario en tu base de datos con el UID de Firebase.
 * 4. Adjunta los datos del usuario, incluyendo el rol y el estado de bloqueo, al objeto `req.user`.
 * 5. Si el usuario está bloqueado, deniega el acceso.
 */
const isAuthenticated = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    // 1. Verificar si el encabezado de autorización existe y tiene el formato correcto.
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Acceso denegado. Token no proporcionado o inválido.' });
    }

    // Usar desestructuración para extraer el token de forma más limpia
    const [bearer, idToken] = authHeader.split(' ');

    try {
        // 2. Verificar el token con Firebase Admin SDK.
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const firebaseUid = decodedToken.uid;

        // 3. Obtener el perfil completo del usuario desde tu base de datos usando el UID de Firebase.
        const userProfileResult = await pool.query(
            `SELECT
                u.user_id,
                u.firebase_uid,
                u.email,
                u.is_blocked,
                r.role_name,
                up.first_name,
                up.last_name,
                up.phone,
                up.city,
                up.profile_picture_url
             FROM users u
             JOIN roles r ON u.role_id = r.role_id
             LEFT JOIN user_profiles up ON u.user_id = up.user_id
             WHERE u.firebase_uid = $1`,
            [firebaseUid]
        );

        const user = userProfileResult.rows[0];

        // 4. Si el usuario no se encuentra en la base de datos, denegar el acceso.
        if (!user) {
            return res.status(403).json({ message: 'Prohibido: Perfil de usuario no encontrado en la base de datos.' });
        }

        // 5. **LÓGICA DE BLOQUEO: Verificar si el usuario está bloqueado**
        if (user.is_blocked) {
            return res.status(403).json({ message: 'Tu cuenta ha sido bloqueada. Por favor, contacta al administrador para más información.' });
        }

        // 6. Adjuntar la información del usuario a la solicitud para uso posterior en las rutas.
        req.user = {
            id: user.user_id,
            firebase_uid: user.firebase_uid,
            email: user.email,
            role_name: user.role_name,
            first_name: user.first_name,
            last_name: user.last_name,
            phone: user.phone,
            city: user.city,
            profile_picture_url: user.profile_picture_url,
            is_blocked: user.is_blocked
        };

        // 7. Continuar con el siguiente middleware o la función de la ruta.
        next();

    } catch (error) {
        console.error('isAuthenticated: Error al verificar Firebase ID Token o al obtener usuario de la DB:', error.message);
        
        // Manejar errores comunes de Firebase para proporcionar mensajes más claros.
        let errorMessage = 'Acceso no autorizado: Token inválido o expirado.';
        if (error.code === 'auth/id-token-expired') {
            errorMessage = 'Acceso no autorizado: La sesión ha expirado. Por favor, vuelve a iniciar sesión.';
        } else if (error.code === 'auth/argument-error' || error.code === 'auth/invalid-id-token') {
            errorMessage = 'Acceso no autorizado: Formato de token inválido.';
        }
        return res.status(403).json({ message: errorMessage });
    }
};

/**
 * @description Middleware para autorizar el acceso basado en roles.
 * Esta función es un 'closure' que recibe un array de roles requeridos.
 * Se asume que `isAuthenticated` ya ha adjuntado el rol del usuario a `req.user`.
 * @param {string[]} requiredRoles - Un array de nombres de roles permitidos.
 */
const authorizeRoles = (requiredRoles) => {
    return (req, res, next) => {
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

// Exportar ambas funciones para que puedan ser utilizadas en las rutas.
module.exports = {
    isAuthenticated,
    authorizeRoles
};
