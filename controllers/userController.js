// D:\Pagina comercial\Backend\controllers\userController.js

const { pool } = require('../db/db');
const admin = require('firebase-admin'); // Necesario para cambiar contraseñas de Firebase y verificar tokens

/**
 * Función auxiliar para limpiar valores null/vacíos en los datos de entrada
 * @param {Object} data - Objeto de datos
 * @returns {Object} - Datos limpios
 */
function cleanInputValues(data) {
    const cleaned = { ...data };
    Object.keys(cleaned).forEach(key => {
        if (cleaned[key] === '' || cleaned[key] === undefined) {
            cleaned[key] = null;
        }
        if (typeof cleaned[key] === 'string' && cleaned[key].trim() === '') {
            cleaned[key] = null;
        }
    });
    return cleaned;
}

/**
 * Endpoint para obtener el perfil completo de un usuario autenticado.
 * Requiere que el usuario esté autenticado y su Firebase UID esté disponible en req.user.firebase_uid.
 */
exports.getUserProfile = async (req, res) => {
    const firebaseUid = req.user.firebase_uid;

    if (!firebaseUid) {
        return res.status(400).json({ message: 'Firebase UID no encontrado en el token de autenticación.' });
    }

    let client;
    try {
        client = await pool.connect();

        const userResult = await client.query(
            `SELECT
                u.user_id, u.firebase_uid, u.email, r.role_name AS role,
                up.first_name, up.last_name, up.phone, up.city,
                up.profile_picture_url
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            LEFT JOIN user_profiles up ON u.user_id = up.user_id
            WHERE u.firebase_uid = $1`,
            [firebaseUid]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({
                message: 'Perfil de usuario no encontrado en la base de datos.'
            });
        }

        let userProfile = userResult.rows[0];
        userProfile = cleanInputValues(userProfile); // Limpia los valores para la respuesta

        res.status(200).json(userProfile);

    } catch (error) {
        console.error('Error en getUserProfile:', error);
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

/**
 * Endpoint para actualizar campos específicos del perfil del usuario.
 * Requiere que el usuario esté autenticado.
 * Ahora espera un objeto con los campos a actualizar (first_name, last_name, phone, city, profile_picture_url).
 * Utiliza INSERT ... ON CONFLICT DO UPDATE para ser robusto con perfiles nuevos.
 */
exports.updateUserProfile = async (req, res) => {
    const firebaseUid = req.user.firebase_uid; // Obtenido del middleware de autenticación
    const { first_name, last_name, phone, city, profile_picture_url } = req.body;

    if (!firebaseUid) {
        return res.status(401).json({ message: 'No autenticado o UID de Firebase no proporcionado.' });
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Inicia una transacción

        // 1. Obtener el user_id de la tabla users
        const userResult = await client.query('SELECT user_id FROM users WHERE firebase_uid = $1', [firebaseUid]);

        if (userResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }
        const userId = userResult.rows[0].user_id;

        // Limpiar los valores de entrada antes de guardar
        const cleanedData = cleanInputValues({ first_name, last_name, phone, city, profile_picture_url });

        // Campos para la inserción y actualización
        const insertFields = ['user_id'];
        const insertValues = [userId];
        const updateSetClauses = [];
        let paramIndex = 2; // El índice para los parámetros de la consulta SQL

        // Añadir campos y valores dinámicamente
        if (cleanedData.first_name !== undefined) {
            insertFields.push('first_name');
            insertValues.push(cleanedData.first_name);
            updateSetClauses.push(`first_name = $${paramIndex++}`);
        }
        if (cleanedData.last_name !== undefined) {
            insertFields.push('last_name');
            insertValues.push(cleanedData.last_name);
            updateSetClauses.push(`last_name = $${paramIndex++}`);
        }
        if (cleanedData.phone !== undefined) {
            insertFields.push('phone');
            insertValues.push(cleanedData.phone);
            updateSetClauses.push(`phone = $${paramIndex++}`);
        }
        if (cleanedData.city !== undefined) {
            insertFields.push('city');
            insertValues.push(cleanedData.city);
            updateSetClauses.push(`city = $${paramIndex++}`);
        }
        if (cleanedData.profile_picture_url !== undefined) {
            insertFields.push('profile_picture_url');
            insertValues.push(cleanedData.profile_picture_url);
            updateSetClauses.push(`profile_picture_url = $${paramIndex++}`);
        }

        // Si no hay campos para actualizar, no hacemos nada (excepto si es una inserción inicial)
        // La condición insertFields.length === 1 significa que solo user_id está presente,
        // lo que indica que no se enviaron otros campos para insertar/actualizar.
        if (insertFields.length === 1 && updateSetClauses.length === 0) {
            await client.query('ROLLBACK');
            return res.status(200).json({ success: true, message: 'No se proporcionaron campos para actualizar.' });
        }

        // Construir la consulta INSERT ... ON CONFLICT DO UPDATE
        const insertPlaceholders = insertValues.map((_, i) => `$${i + 1}`).join(', ');
        const updateSetPlaceholders = updateSetClauses.join(', ');

        const queryText = `
            INSERT INTO user_profiles (${insertFields.join(', ')})
            VALUES (${insertPlaceholders})
            ON CONFLICT (user_id) DO UPDATE SET
                ${updateSetPlaceholders}
                -- , updated_at = NOW()  <-- ¡CAMBIO IMPORTANTE: Eliminada la referencia a updated_at!
            RETURNING *;
        `;

        // Los valores para la cláusula DO UPDATE SET deben venir después de los valores de INSERT
        // y en el mismo orden que se añadieron a updateSetClauses.
        // Los valores para updateSetClauses son los mismos que insertValues (excepto user_id),
        // pero se referencian por su índice de parámetro dinámico.
        // La forma más sencilla es pasar todos los valores en el orden en que se construyeron.
        const finalQueryValues = [userId]; // user_id es el primer valor para INSERT
        // Añadir los valores de los campos que se insertan/actualizan
        if (cleanedData.first_name !== undefined) finalQueryValues.push(cleanedData.first_name);
        if (cleanedData.last_name !== undefined) finalQueryValues.push(cleanedData.last_name);
        if (cleanedData.phone !== undefined) finalQueryValues.push(cleanedData.phone);
        if (cleanedData.city !== undefined) finalQueryValues.push(cleanedData.city);
        if (cleanedData.profile_picture_url !== undefined) finalQueryValues.push(cleanedData.profile_picture_url);


        console.log('SQL Query:', queryText); // Debug: Muestra la consulta SQL generada
        console.log('Query Values:', finalQueryValues); // Debug: Muestra los valores que se pasarán

        await client.query(queryText, finalQueryValues);

        await client.query('COMMIT'); // Confirma la transacción
        res.status(200).json({ success: true, message: 'Perfil actualizado con éxito.' });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK'); // Revertir la transacción en caso de error
        }
        console.error('Error en updateUserProfile:', error);
        console.error('Detalle del error SQL:', error.detail || error.message); // Debug: Más detalle del error SQL
        res.status(500).json({
            success: false,
            message: 'Error interno del servidor al actualizar el perfil.',
            detail: error.message // Envía el mensaje de error para depuración en el frontend
        });
    } finally {
        if (client) {
            client.release();
        }
    }
};

/**
 * Endpoint para cambiar la contraseña del usuario.
 * Solo aplicable para usuarios autenticados con email/password de Firebase.
 * Requiere que el usuario esté autenticado y que envíe la contraseña actual y la nueva.
 */
exports.changePassword = async (req, res) => {
    const firebaseUid = req.user.firebase_uid; // Obtenido del middleware de autenticación
    const { currentPassword, newPassword } = req.body;

    if (!firebaseUid) {
        return res.status(401).json({ message: 'No autenticado o UID de Firebase no proporcionado.' });
    }
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Contraseña actual y nueva son obligatorias.' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ message: 'La nueva contraseña debe tener al menos 6 caracteres.' });
    }

    let userRecord;
    try {
        userRecord = await admin.auth().getUser(firebaseUid);

        const isEmailPasswordUser = userRecord.providerData.some(
            provider => provider.providerId === 'password'
        );

        if (!isEmailPasswordUser) {
            return res.status(403).json({
                message: 'Este método de cambio de contraseña solo es para usuarios de email/contraseña. Utiliza tu proveedor social (ej. Google) para cambiar la contraseña.'
            });
        }

        await admin.auth().updateUser(firebaseUid, {
            password: newPassword
        });

        res.status(200).json({ message: 'Contraseña actualizada con éxito.' });

    } catch (error) {
        console.error('Error en changePassword:', error);
        if (error.code === 'auth/weak-password') {
            return res.status(400).json({ message: 'La nueva contraseña es demasiado débil.' });
        }
        if (error.code === 'auth/user-not-found') {
             return res.status(404).json({ message: 'Usuario no encontrado en Firebase.' });
        }
        res.status(500).json({
            message: 'Error interno del servidor al cambiar la contraseña.',
            detail: error.message
        });
    }
};
