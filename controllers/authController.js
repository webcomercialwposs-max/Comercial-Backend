// D:\Pagina comercial\Backend\controllers\authController.js

const admin = require('firebase-admin');
const { pool } = require('../db/db'); // <--- RUTA CORREGIDA CONFIRMADA

/**
 * Función auxiliar para limpiar valores null/vacíos en el perfil de usuario
 * @param {Object} userProfile - Objeto del perfil de usuario
 * @returns {Object} - Perfil limpio
 */
function cleanUserProfileValues(userProfile) {
    const cleaned = { ...userProfile };

    // Convertir cadenas vacías y valores null a null de JavaScript
    Object.keys(cleaned).forEach(key => {
        if (cleaned[key] === '' || cleaned[key] === null || cleaned[key] === undefined) {
            cleaned[key] = null;
        }
        // Limpiar cadenas con solo espacios
        if (typeof cleaned[key] === 'string' && cleaned[key].trim() === '') {
            cleaned[key] = null;
        }
    });

    return cleaned;
}

console.log("authController.js: Definiendo exports.getUserProfileByFirebaseUid..."); // Log de depuración
exports.getUserProfileByFirebaseUid = async (req, res) => {
    const { firebaseUid } = req.params;

    if (!firebaseUid) {
        return res.status(400).json({ message: 'Firebase UID es obligatorio.' });
    }

    let client;
    try {
        client = await pool.connect();

        // Buscar usuario por firebase_uid
        const userResult = await client.query(
            `SELECT
                u.user_id, u.firebase_uid, u.email, r.role_name,
                up.first_name, up.last_name, up.phone, up.city
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            LEFT JOIN user_profiles up ON u.user_id = up.user_id
            WHERE u.firebase_uid = $1`,
            [firebaseUid]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                message: 'Usuario no encontrado con el Firebase UID proporcionado.'
            });
        }

        let userProfile = userResult.rows[0];

        // Aplicar limpieza de valores
        userProfile = cleanUserProfileValues(userProfile);

        res.status(200).json(userProfile);

    } catch (error) {
        console.error('Error en getUserProfileByFirebaseUid:', error);
        res.status(500).json({
            message: 'Error interno del servidor al obtener el perfil de usuario.',
            detail: error.message
        });
    } finally {
        if (client) {
            client.release();
        }
    }
};

console.log("authController.js: Definiendo exports.handleFirebaseLogin..."); // Log de depuración
/**
 * Maneja el login/registro unificado de usuarios de Firebase.
 * Recibe el ID Token de Firebase y datos adicionales.
 * Verifica el token, busca/crea el usuario en la DB y devuelve su perfil.
 * @param {Object} req - Objeto de solicitud de Express (contiene idToken y additionalData).
 * @param {Object} res - Objeto de respuesta de Express.
 */
exports.handleFirebaseLogin = async (req, res) => {
    const { idToken, additionalData = {} } = req.body;

    if (!idToken) {
        console.log('[DEBUG] ID Token no proporcionado.'); // Log
        return res.status(400).json({ message: 'ID Token es obligatorio.' });
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Inicia una transacción
        console.log('[DEBUG] Transacción iniciada.'); // Log

        // 1. Verificar el ID Token con Firebase Admin SDK
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const { uid, email, displayName, photoURL } = decodedToken;
        const firebaseGivenName = decodedToken.given_name || null;
        const firebaseFamilyName = decodedToken.family_name || null;

        console.log(`[DEBUG] Token decodificado. Firebase UID: ${uid}, Email: ${email}`); // Log detallado

        let userProfile;
        let userId;
        let isNewUser = false; // Flag para determinar si es un registro nuevo

        // 2. Buscar usuario por firebase_uid o email
        // Intentar encontrar el usuario por UID de Firebase primero
        console.log(`[DEBUG] Paso 1: Buscando usuario por Firebase UID: ${uid}`); // Log
        let userResult = await client.query(
            `SELECT
                u.user_id, u.firebase_uid, u.email, r.role_name,
                up.first_name, up.last_name, up.phone, up.city
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            LEFT JOIN user_profiles up ON u.user_id = up.user_id
            WHERE u.firebase_uid = $1`,
            [uid]
        );

        if (userResult.rows.length === 0) {
            console.log(`[DEBUG] Resultado Paso 1: No encontrado por UID. Buscando por email: ${email}`); // Log
            // Si no se encuentra por UID de Firebase, buscar por email (para vincular cuentas)
            userResult = await client.query(
                `SELECT
                    u.user_id, u.firebase_uid, u.email, r.role_name,
                    up.first_name, up.last_name, up.phone, up.city
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                LEFT JOIN user_profiles up ON u.user_id = up.user_id
                WHERE u.email = $1`, // <--- CAMBIO CLAVE AQUÍ: SIN 'AND u.firebase_uid IS NULL'
                [email]
            );

            if (userResult.rows.length > 0) {
                // Usuario encontrado por email (posiblemente sin firebase_uid o con uno diferente)
                userProfile = userResult.rows[0];
                userId = userProfile.user_id;
                console.log(`[DEBUG] Resultado Paso 2: Usuario encontrado por email. user_id: ${userId}, firebase_uid_existente_db: ${userProfile.firebase_uid}`); // Log

                // Si el usuario existe pero no tiene firebase_uid o tiene uno diferente, vincularlo
                // Esta es la lógica para VINCULAR la cuenta, no para lanzar un 409
                if (userProfile.firebase_uid === null || userProfile.firebase_uid !== uid) {
                    console.log(`[DEBUG] Accion: Vinculando o actualizando UID para user_id: ${userId}`); // Log
                    await client.query(
                        'UPDATE users SET firebase_uid = $1, updated_at = NOW() WHERE user_id = $2',
                        [uid, userId]
                    );
                    userProfile.firebase_uid = uid; // Actualizar el objeto de perfil en memoria
                    console.log(`Backend: Usuario existente con email ${email} vinculado al nuevo Firebase UID: ${uid}`);
                } else {
                    // Si ya está vinculado al UID de Firebase (aunque sea diferente al token actual, lo cual es inusual si el token es válido)
                    // o si el UID del token es el mismo, no hacemos nada más que usar el perfil existente.
                    console.warn(`Backend: Usuario existente con email ${email} ya estaba vinculado al UID: ${userProfile.firebase_uid}.`);
                }

                // Opcional: Actualizar email si ha cambiado (aunque Firebase lo maneja en su lado)
                if (userProfile.email !== email) {
                    console.log(`[DEBUG] Accion: Actualizando email para user_id: ${userId} de ${userProfile.email} a ${email}`); // Log
                    await client.query('UPDATE users SET email = $1 WHERE user_id = $2', [email, userId]);
                    userProfile.email = email; // Actualizar el objeto de respuesta
                }

            } else {
                console.log(`[DEBUG] Resultado Paso 2: No encontrado ni por UID ni por email. Esto es un usuario completamente NUEVO.`); // Log
                // Ni por UID de Firebase ni por email. Es un usuario completamente NUEVO.
                console.log(`Backend: Nuevo usuario Firebase, registrando: ${uid} con email: ${email}`);
                isNewUser = true;

                // Obtener el ID del rol por defecto 'Usuario'
                const defaultRoleResult = await client.query('SELECT role_id FROM roles WHERE role_name = $1', ['Usuario']);
                if (defaultRoleResult.rows.length === 0) {
                    throw new Error('Rol por defecto "Usuario" no encontrado en la base de datos. Asegúrate de que existe.');
                }
                const defaultRoleId = defaultRoleResult.rows[0].role_id;

                // Insertar en la tabla 'users'
                console.log(`[DEBUG] Accion: Insertando nuevo usuario en tabla 'users'.`); // Log antes de INSERT
                const userInsertResult = await client.query(
                    'INSERT INTO users (firebase_uid, email, role_id) VALUES ($1, $2, $3) RETURNING user_id',
                    [uid, email, defaultRoleId]
                );
                userId = userInsertResult.rows[0].user_id;
                console.log(`Backend: Nuevo user_id generado: ${userId}`);

                // Lógica para determinar first_name y last_name para el nuevo usuario
                let firstName = additionalData.first_name || firebaseGivenName || null;
                let lastName = additionalData.last_name || firebaseFamilyName || null;

                const firebaseDisplayName = typeof displayName === 'string' ? displayName.trim() : '';
                if (firstName === null && firebaseDisplayName) {
                    const nameParts = firebaseDisplayName.split(' ');
                    firstName = nameParts[0] || null;
                    if (nameParts.length > 1) {
                        lastName = nameParts.slice(1).join(' ') || null;
                    } else {
                        lastName = null;
                    }
                }
                if (firstName === null && email) {
                    const emailPrefix = email.split('@')[0];
                    firstName = emailPrefix.charAt(0).toUpperCase() + emailPrefix.slice(1).replace(/[^a-zA-Z]/g, '');
                    if (firstName === '') {
                        firstName = null;
                    }
                }

                const phone = additionalData.phone || null;
                const city = additionalData.city || null;

                // Insertar en user_profiles
                console.log(`[DEBUG] Accion: Insertando perfil de usuario en tabla 'user_profiles' para user_id: ${userId}`); // Log antes de INSERT
                await client.query(
                    'INSERT INTO user_profiles (user_id, first_name, last_name, phone, city) VALUES ($1, $2, $3, $4, $5)',
                    [userId, firstName, lastName, phone, city]
                );

                // Construir el objeto de perfil para devolver para el nuevo usuario
                userProfile = {
                    user_id: userId,
                    firebase_uid: uid,
                    email: email,
                    role_name: 'Usuario', // Rol por defecto
                    first_name: firstName,
                    last_name: lastName,
                    phone: phone,
                    city: city
                };
            }
        } else {
            // Usuario encontrado por UID de Firebase directamente (caso más común de re-login)
            userProfile = userResult.rows[0];
            userId = userProfile.user_id;
            console.log(`[DEBUG] Resultado Paso 1: Usuario encontrado por UID directamente. user_id: ${userId}`); // Log
            console.log(`Backend: Usuario existente encontrado por UID: ${uid}`);

            // Actualizar email si ha cambiado (aunque Firebase lo maneja en su lado)
            if (userProfile.email !== email) {
                console.log(`[DEBUG] Accion: Actualizando email para user_id: ${userId} de ${userProfile.email} a ${email}`); // Log
                await client.query('UPDATE users SET email = $1 WHERE user_id = $2', [email, userId]);
                userProfile.email = email; // Actualizar el objeto de respuesta
            }
        }

        // ⭐ APLICAR LIMPIEZA: Asegurarse de que los valores null/vacíos sean null de JavaScript
        userProfile = cleanUserProfileValues(userProfile);
        console.log(`[DEBUG] Perfil de usuario final para respuesta:`, userProfile); // Log del perfil final

        // Si se solicitó un rol específico (ej. en un formulario de registro con rol solicitado)
        // Esto solo se procesa para nuevos usuarios o si el rol actual es el por defecto 'Usuario'
        if (additionalData.requested_role_name && userProfile.role_name === 'Usuario') {
            console.log(`[DEBUG] Procesando petición de rol: ${additionalData.requested_role_name}`); // Log
            const requestedRoleResult = await client.query('SELECT role_id FROM roles WHERE role_name = $1', [additionalData.requested_role_name]);
            if (requestedRoleResult.rows.length === 0) {
                console.warn(`Rol solicitado "${additionalData.requested_role_name}" no encontrado. Ignorando petición.`);
            } else {
                const requestedRoleId = requestedRoleResult.rows[0].role_id;
                const existingRoleRequest = await client.query(
                    'SELECT * FROM role_requests WHERE user_id = $1 AND requested_role_id = $2 AND status = $3',
                    [userId, requestedRoleId, 'pending']
                );

                if (existingRoleRequest.rows.length === 0) {
                    await client.query('INSERT INTO role_requests (user_id, requested_role_id, status) VALUES ($1, $2, $3)', [userId, requestedRoleId, 'pending']);
                    console.log(`Petición de rol para ${additionalData.requested_role_name} creada.`);
                } else {
                    console.log(`Petición de rol para ${additionalData.requested_role_name} ya existe y está pendiente.`);
                }
            }
        }

        await client.query('COMMIT'); // Confirmar la transacción
        console.log('[DEBUG] Transacción confirmada. Enviando respuesta 200 OK.'); // Log
        res.status(200).json(userProfile); // Devolver 200 OK con el perfil

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK'); // Revertir la transacción en caso de error
            console.log('[DEBUG] Transacción revertida debido a un error.'); // Log
        }
        console.error('Error en handleFirebaseLogin:', error);
        if (error.code === '23505') {
            // Este es el error de duplicidad de UNIQUE constraint, si la lógica anterior fallara
            console.log('[DEBUG] Error 23505 detectado. Enviando respuesta 409 Conflict.'); // Log
            return res.status(409).json({ message: 'Ya existe una cuenta con este correo electrónico o UID de Firebase. Por favor, inicia sesión manualmente si es tu cuenta, o usa un correo diferente.', detail: error.detail });
        }
        res.status(500).json({ message: 'Error interno del servidor al manejar login/registro Firebase: ' + error.message, detail: error.detail, code: error.code });
    } finally {
        if (client) {
            client.release();
            console.log('[DEBUG] Cliente de base de datos liberado.'); // Log
        }
    }
};

// Agrega este log para confirmar la exportación final
console.log("authController.js: Módulo authController exportado.");
console.log("authController.js: exports.handleFirebaseLogin es:", typeof exports.handleFirebaseLogin);
console.log("authController.js: exports.getUserProfileByFirebaseUid es:", typeof exports.getUserProfileByFirebaseUid);