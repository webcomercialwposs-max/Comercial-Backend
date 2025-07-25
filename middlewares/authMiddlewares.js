// Backend/middlewares/authMiddlewares.js
const admin = require('../firebaseAdmin'); // Importa la instancia inicializada del Firebase Admin SDK
const pool = require('../db/db.js').pool; // Necesario para buscar el rol del usuario en la DB

/**
 * Middleware para verificar el ID Token de Firebase.
 * Extrae el token del encabezado Authorization, lo verifica con Firebase Admin SDK,
 * y adjunta la información del usuario (incluyendo el rol de tu DB) al objeto req.user.
 */
const authenticateFirebaseToken = async (req, res, next) => {
    console.log('\n--- authenticateFirebaseToken: Iniciando verificación ---');
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('authenticateFirebaseToken: Error 401 - No se proporcionó token o el formato es incorrecto.');
        return res.status(401).json({ message: 'Acceso denegado. Token no proporcionado o inválido.' });
    }

    const idToken = authHeader.split(' ')[1];
    console.log('authenticateFirebaseToken: Token extraído. Longitud:', idToken.length);
    // 🔥 NUEVO LOG: Imprime los primeros 50 caracteres del token para inspección
    console.log('authenticateFirebaseToken: Token (primeros 50 chars):', idToken.substring(0, 50) + '...');


    try {
        // 1. Verificar el token con Firebase Admin SDK
        console.log('authenticateFirebaseToken: Verificando token con Firebase Admin SDK...');
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const firebaseUid = decodedToken.uid;
        console.log('authenticateFirebaseToken: Token de Firebase verificado con éxito. UID:', firebaseUid, 'Email:', decodedToken.email);

        // 2. Obtener el perfil completo del usuario desde tu base de datos usando el UID de Firebase
        console.log('authenticateFirebaseToken: Buscando perfil en DB para Firebase UID:', firebaseUid);
        const userProfileResult = await pool.query(
            `SELECT
                u.user_id,
                u.firebase_uid,
                u.email,
                r.role_name,
                up.first_name,
                up.last_name,
                up.phone,
                up.city
             FROM users u
             JOIN roles r ON u.role_id = r.role_id
             LEFT JOIN user_profiles up ON u.user_id = up.user_id
             WHERE u.firebase_uid = $1`,
            [firebaseUid]
        );

        const user = userProfileResult.rows[0];

        if (!user) {
            console.warn(`authenticateFirebaseToken: Error 403 - Usuario autenticado por Firebase (${firebaseUid}) pero no encontrado en la DB.`);
            // Cambiado de 404 a 403 para una mejor semántica de autorización
            return res.status(403).json({ message: 'Prohibido: Perfil de usuario no encontrado en la base de datos o no autorizado para esta acción.' });
        }

        // 3. Adjuntar la información del usuario (incluyendo el rol de tu DB) a la solicitud
        req.user = {
            id: user.user_id, // Tu ID interno de DB
            firebase_uid: user.firebase_uid,
            email: user.email,
            role_name: user.role_name, // Rol obtenido de tu DB
            first_name: user.first_name,
            last_name: user.last_name,
            phone: user.phone,
            city: user.city
        };
        console.log('authenticateFirebaseToken: Usuario autenticado y perfil cargado en req.user:', req.user.email, 'Rol:', req.user.role_name);
        next(); // Continuar con la siguiente función middleware/ruta

    } catch (error) {
        console.error('authenticateFirebaseToken: Error al verificar Firebase ID Token o al obtener usuario de la DB:', error.message);
        let errorMessage = 'Acceso no autorizado: Token inválido o expirado.';
        if (error.code === 'auth/id-token-expired') {
            errorMessage = 'Acceso no autorizado: La sesión ha expirado. Por favor, vuelve a iniciar sesión.';
        } else if (error.code === 'auth/argument-error' || error.code === 'auth/invalid-id-token') {
            errorMessage = 'Acceso no autorizado: Formato de token inválido.';
        }
        // Este 403 es correcto si el TOKEN es inválido o hay un problema con Firebase Admin SDK
        return res.status(403).json({ message: errorMessage }); 
    } finally {
        console.log('--- authenticateFirebaseToken: Verificación finalizada ---');
    }
};

/**
 * Middleware para autorizar roles.
 * Se basa en que req.user ya ha sido poblado por authenticateFirebaseToken.
 */
const authorizeRoles = (requiredRoles) => {
    return (req, res, next) => {
        console.log(`\n--- authorizeRoles: Verificando rol. Rol de usuario actual: ${req.user?.role_name}. Roles requeridos: ${requiredRoles.join(', ')} ---`);
        if (!req.user || !req.user.role_name) {
            console.warn('authorizeRoles: Rol de usuario no disponible en req.user. Denegando acceso.');
            return res.status(403).json({ message: 'Acceso denegado: Rol de usuario no disponible.' });
        }

        const userRoleName = req.user.role_name;

        // 🔥 IMPORTANTE: Asegúrate de que el string 'Administrador' (o el rol requerido)
        // coincida EXACTAMENTE con el valor en tu base de datos.
        if (!requiredRoles.includes(userRoleName)) {
            console.warn(`authorizeRoles: Acceso denegado para rol '${userRoleName}'. Se requiere uno de: ${requiredRoles.join(', ')}.`);
            return res.status(403).json({ message: `Acceso denegado: Se requiere uno de los siguientes roles: ${requiredRoles.join(', ')}.` });
        }
        console.log(`authorizeRoles: Rol '${userRoleName}' autorizado. Acceso concedido.`);
        next();
    };
};

// Exportar AMBAS funciones como propiedades de un objeto
module.exports = {
    authenticateFirebaseToken,
    authorizeRoles
};
