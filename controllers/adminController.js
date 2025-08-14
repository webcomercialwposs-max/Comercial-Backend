// backend/controllers/adminController.js
const { pool } = require('../db/db.js'); // Asegúrate de que la ruta a tu archivo db.js sea correcta
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Si usas Firebase Admin SDK para deshabilitar/habilitar usuarios directamente en Firebase Auth
// const admin = require('firebase-admin'); // Descomentar si lo necesitas

// Función para obtener todas las solicitudes de rol pendientes
exports.getPendingRoleRequests = async (req, res) => {
    let client;
    try {
        client = await pool.connect();
        const result = await client.query(`
            SELECT
                rr.request_id,
                rr.user_id,
                u.email,
                up.first_name,
                up.last_name,
                r.role_name AS requested_role_name,
                rr.status,
                rr.request_date,
                rr.admin_notes,
                rr.response_date
            FROM
                role_requests rr
            JOIN
                users u ON rr.user_id = u.user_id
            LEFT JOIN
                user_profiles up ON u.user_id = up.user_id
            JOIN
                roles r ON rr.requested_role_id = r.role_id
            WHERE
                rr.status = 'pending'
            ORDER BY
                rr.request_date DESC;
        `);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error al obtener solicitudes de rol pendientes:', error);
        res.status(500).json({ message: 'Error interno del servidor al obtener solicitudes de rol.' });
    } finally {
        if (client) {
            client.release();
        }
    }
};

// Función para aprobar una solicitud de rol
exports.approveRoleRequest = async (req, res) => {
    const { request_id } = req.params;
    let client;

    try {
        client = await pool.connect();
        await client.query('BEGIN');

        const requestResult = await client.query(
            `SELECT user_id, requested_role_id FROM role_requests WHERE request_id = $1 AND status = 'pending'`,
            [request_id]
        );

        if (requestResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: 'Solicitud de rol no encontrada o ya procesada.' });
        }

        const { user_id, requested_role_id } = requestResult.rows[0];

        await client.query(
            `UPDATE users SET role_id = $1 WHERE user_id = $2`,
            [requested_role_id, user_id]
        );

        await client.query(
            `UPDATE role_requests SET status = 'approved', response_date = NOW() WHERE request_id = $1`,
            [request_id]
        );

        await client.query('COMMIT');
        res.status(200).json({ message: 'Solicitud de rol aprobada y rol de usuario actualizado.' });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        console.error('Error al aprobar solicitud de rol:', error);
        res.status(500).json({ message: 'Error interno del servidor al aprobar la solicitud.' });
    } finally {
        if (client) {
            client.release();
        }
    }
};

// Función para rechazar una solicitud de rol
exports.rejectRoleRequest = async (req, res) => {
    const { request_id } = req.params;
    let client;

    try {
        client = await pool.connect();
        const result = await client.query(
            `UPDATE role_requests SET status = 'rejected', response_date = NOW() WHERE request_id = $1 AND status = 'pending' RETURNING *`,
            [request_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Solicitud de rol no encontrada o ya procesada.' });
        }

        res.status(200).json({ message: 'Solicitud de rol rechazada.' });

    } catch (error) {
        console.error('Error al rechazar solicitud de rol:', error);
        res.status(500).json({ message: 'Error interno del servidor al rechazar la solicitud.' });
    } finally {
        if (client) {
            client.release();
        }
    }
};

// Función para obtener todos los usuarios con sus perfiles, roles y estado de bloqueo
exports.fetchAllUsers = async (req, res) => {
    console.log('adminController: Accediendo a fetchAllUsers. Usuario autenticado:', req.user?.email, 'Rol:', req.user?.role_name);
    let client;
    try {
        client = await pool.connect();
        const sqlQuery = `
            SELECT
                u.user_id,
                u.firebase_uid,
                u.email,
                r.role_name,
                up.first_name,
                up.last_name,
                up.phone,
                up.city,
                u.created_at AS registration_date,
                COALESCE(rr.status, 'none') as admin_request_status,
                u.is_blocked -- Agregado para obtener el estado de bloqueo
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            LEFT JOIN user_profiles up ON u.user_id = up.user_id
            LEFT JOIN role_requests rr ON u.user_id = rr.user_id
                AND rr.requested_role_id = (SELECT role_id FROM roles WHERE role_name = 'Administrador')
                AND rr.status = 'pending'
            ORDER BY u.created_at DESC`;

        console.log("SQL Query being executed:", sqlQuery);

        const result = await client.query(sqlQuery);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('adminController: Error al obtener todos los usuarios:', error);
        res.status(500).json({ message: 'Error interno del servidor al obtener usuarios.' });
    } finally {
        if (client) {
            client.release();
        }
    }
};

// Función para obtener todos los roles disponibles
exports.fetchRoles = async (req, res) => {
    console.log('adminController: Solicitud para obtener todos los roles.');
    let client;
    try {
        client = await pool.connect();
        const result = await client.query('SELECT role_id, role_name FROM roles ORDER BY role_name ASC');
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('adminController: Error al obtener todos los roles disponibles:', error);
        res.status(500).json({ message: 'Error interno del servidor al obtener roles.' });
    } finally {
        if (client) {
            client.release();
        }
    }
};

// Función para actualizar el rol de un usuario
exports.updateUserRole = async (req, res) => {
    const { userId } = req.params;
    const { role_name: newRoleName } = req.body;

    if (!newRoleName) {
        return res.status(400).json({ message: 'El nuevo nombre de rol es requerido.' });
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');

        const roleResult = await client.query('SELECT role_id FROM roles WHERE role_name = $1', [newRoleName]);
        if (roleResult.rows.length === 0) {
            throw new Error(`Rol '${newRoleName}' no encontrado en la base de datos.`);
        }
        const newRoleId = roleResult.rows[0].role_id;
        console.log(`adminController: ID del nuevo rol para '${newRoleName}': ${newRoleId}`);

        const result = await client.query(
            'UPDATE users SET role_id = $1 WHERE user_id = $2 RETURNING user_id, role_id',
            [newRoleId, userId]
        );

        if (result.rows.length === 0) {
            throw new Error('Usuario no encontrado.');
        }

        if (newRoleName === 'Administrador') {
            await client.query(
                `UPDATE role_requests
                 SET status = 'approved', response_date = NOW()
                 WHERE user_id = $1 AND requested_role_id = (SELECT role_id FROM roles WHERE role_name = 'Administrador') AND status = 'pending'`,
                [userId]
            );
            console.log(`adminController: Solicitudes de admin pendientes para usuario ${userId} marcadas como aprobadas.`);
        } else if (newRoleName === 'Usuario') {
            await client.query(
                `UPDATE role_requests
                 SET status = 'rejected', response_date = NOW()
                 WHERE user_id = $1 AND requested_role_id = (SELECT role_id FROM roles WHERE role_name = 'Administrador') AND status = 'pending'`,
                [userId]
            );
            console.log(`adminController: Solicitudes de admin pendientes para usuario ${userId} marcadas como rechazadas.`);
        }

        await client.query('COMMIT');
        res.status(200).json({ message: 'Rol de usuario actualizado con éxito.', updatedUser: result.rows[0] });
    } catch (error) {
        if (client) {
            await client.query('ROLLBACK');
        }
        console.error('Error al actualizar el rol del usuario:', error);
        res.status(500).json({ message: error.message || 'Error interno del servidor al actualizar el rol.' });
    } finally {
        if (client) {
            client.release();
        }
    }
};

// Función para eliminar un usuario
exports.deleteUser = async (req, res) => {
    const { userId } = req.params;
    console.log(`adminController: Solicitud para eliminar usuario con ID: ${userId}.`);

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Iniciar transacción

        // Eliminar de tablas relacionadas primero para evitar errores de FK
        await client.query('DELETE FROM user_profiles WHERE user_id = $1', [userId]);
        console.log(`adminController: Perfil de usuario ${userId} eliminado.`);

        await client.query('DELETE FROM role_requests WHERE user_id = $1', [userId]);
        console.log(`adminController: Peticiones de rol de usuario ${userId} eliminadas.`);

        // *** LOG ADICIONAL: Verificar si se llega a este punto antes del DELETE final ***
        console.log(`adminController: Intentando eliminar de la tabla 'users' el ID: ${userId}`);
        const result = await client.query('DELETE FROM users WHERE user_id = $1 RETURNING *', [userId]);

        if (result.rows.length === 0) {
            // *** LOG ADICIONAL: Si el usuario no fue encontrado para eliminar ***
            console.warn(`adminController: Usuario con ID ${userId} no encontrado en la tabla 'users' para eliminar.`);
            throw new Error('Usuario no encontrado para eliminar.');
        }

        // *** LOG ADICIONAL: Si el DELETE de 'users' fue exitoso ***
        console.log(`adminController: Usuario con ID ${userId} eliminado exitosamente de la tabla 'users'.`);
        await client.query('COMMIT'); // Confirmar la transacción
        console.log(`adminController: Transacción de eliminación para usuario ${userId} confirmada.`);

        res.status(200).json({ message: 'Usuario eliminado con éxito.' });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK'); // Revertir la transacción en caso de error
            // *** LOG ADICIONAL: Mensaje de transacción revertida ***
            console.error(`adminController: Transacción revertida para usuario ${userId} debido a un error.`);
        }
        // *** LOG ADICIONAL CRÍTICO: Imprime el objeto de error COMPLETO ***
        console.error('adminController: Error CRÍTICO al eliminar usuario:', error);
        // Si el error tiene un 'detail' (común en errores de PostgreSQL como FK), inclúyelo en la respuesta
        const errorMessage = error.detail || error.message || 'Error interno del servidor al eliminar usuario.';
        res.status(500).json({ message: errorMessage });
    } finally {
        if (client) {
            client.release(); // Liberar el cliente de la pool
        }
    }
};

// NUEVA FUNCIÓN: Para bloquear/desbloquear usuarios por Firebase UID
exports.toggleUserBlockStatus = async (req, res) => {
    const { firebaseUid } = req.params; // Obtiene el Firebase UID de los parámetros de la URL
    const { isBlocked } = req.body;     // Obtiene el nuevo estado de bloqueo (boolean) del cuerpo de la solicitud

    console.log(`adminController: Recibida solicitud para ${isBlocked ? 'bloquear' : 'desbloquear'} usuario con Firebase UID: ${firebaseUid}`);
    console.log(`adminController: Estado de bloqueo solicitado: ${isBlocked}`);

    if (typeof isBlocked === 'undefined' || typeof isBlocked !== 'boolean') {
        return res.status(400).json({ message: 'El estado de bloqueo (isBlocked) es requerido y debe ser un booleano.' });
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Iniciar transacción

        // 1. Encontrar al usuario en la base de datos por su firebase_uid
        const userResult = await client.query('SELECT user_id, firebase_uid, is_blocked FROM users WHERE firebase_uid = $1', [firebaseUid]);

        if (userResult.rows.length === 0) {
            await client.query('ROLLBACK');
            console.warn(`adminController: Usuario con Firebase UID ${firebaseUid} no encontrado en la base de datos.`);
            return res.status(404).json({ message: 'Usuario no encontrado para bloquear/desbloquear.' });
        }

        const user = userResult.rows[0];
        console.log(`adminController: Usuario encontrado en DB: ID=${user.user_id}, UID=${user.firebase_uid}, Bloqueado actualmente=${user.is_blocked}`);

        // 2. Actualizar el estado is_blocked en la tabla 'users'
        const updateResult = await client.query('UPDATE users SET is_blocked = $1 WHERE user_id = $2 RETURNING *', [isBlocked, user.user_id]);

        if (updateResult.rows.length === 0) {
            await client.query('ROLLBACK');
            console.error(`adminController: Fallo al actualizar el estado de bloqueo para el usuario con ID ${user.user_id}.`);
            return res.status(500).json({ message: 'Error al actualizar el estado de bloqueo del usuario.' });
        }

        const updatedUser = updateResult.rows[0];
        console.log(`adminController: Usuario ${updatedUser.firebase_uid} ${isBlocked ? 'bloqueado' : 'desbloqueado'} exitosamente en la base de datos.`);

        // 3. (Opcional) Si también estás usando Firebase Authentication para gestionar el estado de "desactivado"
        //    Descomenta y adapta esta sección si es relevante para tu flujo.
        /*
        if (admin) { // Asegúrate de que `admin` de firebase-admin esté importado y configurado
            try {
                await admin.auth().updateUser(firebaseUid, { disabled: isBlocked });
                console.log(`adminController: Usuario ${firebaseUid} ${isBlocked ? 'deshabilitado' : 'habilitado'} en Firebase Authentication.`);
            } catch (firebaseError) {
                console.error(`adminController: Error al actualizar el estado de Firebase Auth para ${firebaseUid}:`, firebaseError.message);
                // Decide si revertir la transacción de DB si Firebase Auth falla
                // await client.query('ROLLBACK');
                // return res.status(500).json({ message: 'Error al actualizar el estado en Firebase Authentication.' });
                // O solo loggear y continuar si la DB es la fuente principal de verdad
            }
        }
        */

        await client.query('COMMIT'); // Confirmar la transacción
        res.status(200).json({ message: `Usuario ${isBlocked ? 'bloqueado' : 'desbloqueado'} exitosamente.`, updatedUser: updatedUser });

    } catch (error) {
        if (client) {
            await client.query('ROLLBACK'); // Revertir la transacción en caso de error
        }
        console.error('adminController: Error al bloquear/desbloquear usuario:', error);
        res.status(500).json({ message: error.message || 'Error interno del servidor al procesar la solicitud de bloqueo/desbloqueo.' });
    } finally {
        if (client) {
            client.release();
        }
    }
};