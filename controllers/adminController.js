// controllers/adminController.js
const { pool } = require('../db/db.js'); // Asegúrate de que la ruta sea correcta
const jwt = require('jsonwebtoken');

// controllers/adminController.js
// ...
exports.getPendingRoleRequests = async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT
                rr.request_id,
                rr.user_id,
                u.username,
                u.email,
                up.first_name,
                up.last_name,
                up.identification,
                up.phone,
                up.address,
                up.city,
                r.role_name AS requested_role_name,
                rr.status
                -- Se eliminan rr.created_at, rr.updated_at si no existen en role_requests
            FROM role_requests rr
            JOIN users u ON rr.user_id = u.user_id
            JOIN user_profiles up ON u.user_id = up.user_id
            JOIN roles r ON rr.requested_role_id = r.role_id
            WHERE rr.status = 'pending'
            ORDER BY rr.request_id DESC; -- Ordena por ID de la petición si no hay fecha de creación
        `);
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error al obtener peticiones de rol pendientes:', error);
        res.status(500).json({ message: 'Error interno del servidor al obtener peticiones de rol.' });
    }
};
// ...


// Aprobar una petición de rol
exports.approveRoleRequest = async (req, res) => {
    const { request_id } = req.params;
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Iniciar transacción

        // 1. Obtener la petición de rol
        const requestResult = await client.query('SELECT user_id, requested_role_id FROM role_requests WHERE request_id = $1 AND status = \'pending\'', [request_id]);

        if (requestResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ message: 'Petición de rol pendiente no encontrada.' });
        }

        const { user_id, requested_role_id } = requestResult.rows[0];

        // 2. Actualizar el rol del usuario en la tabla 'users'
        await client.query('UPDATE users SET role_id = $1 WHERE user_id = $2', [requested_role_id, user_id]);

        // 3. Actualizar el estado de la petición de rol a 'approved'
        await client.query('UPDATE role_requests SET status = \'approved\' WHERE request_id = $1', [request_id]);

        await client.query('COMMIT'); // Confirmar transacción
        res.status(200).json({ message: 'Petición de rol aprobada y rol de usuario actualizado exitosamente.' });
    } catch (error) {
        if (client) {
            await client.query('ROLLBACK'); // Revertir transacción en caso de error
        }
        console.error('Error al aprobar petición de rol:', error);
        res.status(500).json({ message: 'Error interno del servidor al aprobar petición de rol.' });
    } finally {
        if (client) {
            client.release();
        }
    }
};

// Rechazar una petición de rol
exports.rejectRoleRequest = async (req, res) => {
    const { request_id } = req.params;
    try {
        const result = await pool.query(
    'UPDATE role_requests SET status = \'rejected\' WHERE request_id = $1 AND status = \'pending\' RETURNING *',
    [request_id]
);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Petición de rol pendiente no encontrada o ya procesada.' });
        }

        res.status(200).json({ message: 'Petición de rol rechazada exitosamente.' });
    } catch (error) {
        console.error('Error al rechazar petición de rol:', error);
        res.status(500).json({ message: 'Error interno del servidor al rechazar petición de rol.' });
    }
};