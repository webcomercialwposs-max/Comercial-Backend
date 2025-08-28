// controllers/authController.js

const admin = require('firebase-admin');
const { pool } = require('../db/db.js');
const { securityLogger } = require('../middlewares/security.js');
const validator = require('validator');

/**
 * Consultas preparadas para prevenir SQL injection
 */
const PREPARED_QUERIES = {
    getUserByFirebaseUid: `
        SELECT
            u.user_id, u.firebase_uid, u.email, u.is_blocked, r.role_name,
            up.first_name, up.last_name, up.phone, up.city, up.profile_picture_url
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        LEFT JOIN user_profiles up ON u.user_id = up.user_id
        WHERE u.firebase_uid = $1`,

    getUserByEmail: `
        SELECT
            u.user_id, u.firebase_uid, u.email, u.is_blocked, r.role_name,
            up.first_name, up.last_name, up.phone, up.city, up.profile_picture_url
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        LEFT JOIN user_profiles up ON u.user_id = up.user_id
        WHERE u.email = $1`,

    getUserById: `
        SELECT
            u.user_id, u.firebase_uid, u.email, u.is_blocked, r.role_name,
            up.first_name, up.last_name, up.phone, up.city, up.profile_picture_url
        FROM users u
        JOIN roles r ON u.role_id = r.role_id
        LEFT JOIN user_profiles up ON u.user_id = up.user_id
        WHERE u.user_id = $1`,

    getDefaultRole: "SELECT role_id FROM roles WHERE role_name = 'Usuario' LIMIT 1",

    insertUser: `
        INSERT INTO users (firebase_uid, email, role_id)
        VALUES ($1, $2, $3)
        RETURNING user_id`,

    updateFirebaseUid: `
        UPDATE users SET firebase_uid = $1 WHERE user_id = $2`,

    upsertProfile: `
        INSERT INTO user_profiles (user_id, first_name, last_name, phone, city, profile_picture_url)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (user_id) DO UPDATE SET
        first_name = COALESCE(EXCLUDED.first_name, user_profiles.first_name),
        last_name = COALESCE(EXCLUDED.last_name, user_profiles.last_name),
        phone = COALESCE(EXCLUDED.phone, user_profiles.phone),
        city = COALESCE(EXCLUDED.city, user_profiles.city),
        profile_picture_url = COALESCE(EXCLUDED.profile_picture_url, user_profiles.profile_picture_url)`
};

/**
 * Helper seguro para actualizar perfil de usuario
 */
const secureUpsertUserProfile = async (client, userId, validatedData) => {
    if (!validatedData || Object.keys(validatedData).length === 0) {
        return;
    }

    try {
        await client.query(PREPARED_QUERIES.upsertProfile, [
            userId,
            validatedData.first_name || null,
            validatedData.last_name || null,
            validatedData.phone || null,
            validatedData.city || null,
            validatedData.profile_picture_url || null
        ]);
    } catch (error) {
        console.error('🔴 ERROR en secureUpsertUserProfile:', error.message, 'Código:', error.code, 'UserID:', userId);
        securityLogger.error('Error in secureUpsertUserProfile', {
            userId,
            error: error.message,
            code: error.code
        });
        throw error;
    }
};

/**
 * 🛠️ FUNCIONES DE VALIDACIÓN CORREGIDAS
 * Ahora permiten campos opcionales (null, '') sin lanzar un error.
 */
const sanitizeAndValidate = {
    validateName: (name, fieldName = 'Nombre') => {
        if (name === null || name === '') {
            return null;
        }
        if (typeof name !== 'string') {
            throw new Error(`${fieldName} debe ser texto.`);
        }
        const sanitized = name.trim().replace(/\s+/g, ' ');
        if (sanitized.length < 2) {
            throw new Error(`${fieldName} debe tener al menos 2 caracteres.`);
        }
        if (sanitized.length > 50) {
            throw new Error(`${fieldName} no puede exceder 50 caracteres.`);
        }
        const nameRegex = /^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄČĆĘÈÉÊËĖĮÌÍÎÏŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑÇČŠŽ\s\-'\.]+$/;
        if (!nameRegex.test(sanitized)) {
            throw new Error(`${fieldName} contiene caracteres no válidos.`);
        }
        return sanitized;
    },
    validatePhone: (phone) => {
        if (phone === null || phone === '') {
            return null;
        }
        if (typeof phone !== 'string') {
            throw new Error('Teléfono debe ser texto.');
        }
        const sanitized = phone.trim().replace(/[^\d+\-\s()]/g, '');
        if (sanitized.length < 7) {
            throw new Error('Teléfono debe tener al menos 7 dígitos.');
        }
        if (sanitized.length > 20) {
            throw new Error('Teléfono no puede exceder 20 caracteres.');
        }
        const phoneRegex = /^[\+]?[\d\s\-\(\)]{7,20}$/;
        if (!phoneRegex.test(sanitized)) {
            throw new Error('Formato de teléfono no válido.');
        }
        return sanitized;
    },
    validateCity: (city) => {
        if (city === null || city === '') {
            return null;
        }
        if (typeof city !== 'string') {
            throw new Error('Ciudad debe ser texto.');
        }
        const sanitized = city.trim().replace(/\s+/g, ' ');
        if (sanitized.length < 2) {
            throw new Error('Ciudad debe tener al menos 2 caracteres.');
        }
        if (sanitized.length > 100) {
            throw new Error('Ciudad no puede exceder 100 caracteres.');
        }
        const cityRegex = /^[a-zA-ZàáâäãåąčćęèéêëėįìíîïłńòóôöõøùúûüųūÿýżźñçčšžÀÁÂÄÃÅĄČĆĘÈÉÊËĖĮÌÍÎÏŁŃÒÓÔÖÕØÙÚÛÜŲŪŸÝŻŹÑÇČŠŽ\s\-'\.]+$/;
        if (!cityRegex.test(sanitized)) {
            throw new Error('Ciudad contiene caracteres no válidos.');
        }
        return sanitized;
    },
    validateProfilePictureUrl: (url) => {
        if (url === null || url === '') {
            return null;
        }
        if (typeof url !== 'string') {
            throw new Error('URL de imagen debe ser texto.');
        }
        const sanitized = url.trim();
        if (sanitized.length > 500) {
            throw new Error('URL de imagen no puede exceder 500 caracteres.');
        }
        if (!validator.isURL(sanitized, { protocols: ['http', 'https'], require_protocol: true, require_valid_protocol: true, allow_underscores: false, require_host: true, require_port: false, allow_trailing_dot: false, allow_protocol_relative_urls: false })) {
            throw new Error('Formato de URL de imagen no válido.');
        }
        const imageExtensions = /\.(jpg|jpeg|png|gif|webp|bmp)(\?.*)?$/i;
        if (!imageExtensions.test(sanitized)) {
            throw new Error('La URL debe ser una imagen válida (jpg, jpeg, png, gif, webp, bmp).');
        }
        return sanitized;
    }
};

const validateEmailQuery = (email) => {
    if (!email || typeof email !== 'string') {
        throw new Error('Email es requerido y debe ser texto.');
    }
    const sanitized = email.trim().toLowerCase();
    if (!validator.isEmail(sanitized)) {
        throw new Error('Formato de email no válido.');
    }
    if (sanitized.length > 254) {
        throw new Error('Email no puede exceder 254 caracteres.');
    }
    return sanitized;
};

const validateAndSanitizeAdditionalData = (rawData) => {
    if (!rawData || typeof rawData !== 'object') {
        return {};
    }
    const validatedData = {};
    try {
        if (rawData.first_name !== undefined) {
            validatedData.first_name = sanitizeAndValidate.validateName(rawData.first_name, 'Nombre');
        }
        if (rawData.last_name !== undefined) {
            validatedData.last_name = sanitizeAndValidate.validateName(rawData.last_name, 'Apellido');
        }
        if (rawData.phone !== undefined) {
            validatedData.phone = sanitizeAndValidate.validatePhone(rawData.phone);
        }
        if (rawData.city !== undefined) {
            validatedData.city = sanitizeAndValidate.validateCity(rawData.city);
        }
        if (rawData.profile_picture_url !== undefined) {
            validatedData.profile_picture_url = sanitizeAndValidate.validateProfilePictureUrl(rawData.profile_picture_url);
        }
        return validatedData;
    } catch (error) {
        console.error('🔴 ERROR en validateAndSanitizeAdditionalData:', error.message);
        securityLogger.warn('Data validation failed', { error: error.message, rawDataKeys: Object.keys(rawData) });
        throw new Error(`Datos inválidos: ${error.message}`);
    }
};

/**
 * Manejo seguro del login/registro de Firebase
 */
const handleFirebaseLogin = async (req, res) => {
    const startTime = Date.now();
    let client;
    let email = null;
    let firebaseUid = null;

    try {
        // 1. Validación inicial del token
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            console.error('🔴 ERROR de autenticación: Token no proporcionado o inválido.');
            securityLogger.warn('Authentication attempt without proper token', {
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            return res.status(401).json({
                message: 'Acceso denegado. Token no proporcionado o inválido.'
            });
        }

        const idToken = authHeader.split(' ')[1];

        // Validación básica del token
        if (!idToken || idToken.length < 100) {
            console.error('🔴 ERROR de autenticación: Token muy corto o vacío.');
            return res.status(401).json({
                message: 'Token de autenticación inválido.'
            });
        }

        // 2. Conectar a BD y comenzar transacción
        client = await pool.connect();
        await client.query('BEGIN');

        // 3. Verificar token con Firebase (con timeout)
        const tokenVerificationPromise = admin.auth().verifyIdToken(idToken);
        const timeoutPromise = new Promise((_, reject) =>
            setTimeout(() => reject(new Error('Token verification timeout')), 10000)
        );

        const decodedToken = await Promise.race([tokenVerificationPromise, timeoutPromise]);

        firebaseUid = decodedToken.uid;
        email = decodedToken.email;

        // 4. Validaciones de token decodificado
        if (!firebaseUid || !email) {
            await client.query('ROLLBACK');
            console.error('🔴 ERROR de autenticación: UID o email no encontrados en el token decodificado.');
            securityLogger.warn('Invalid Firebase token data', {
                hasUid: !!firebaseUid,
                hasEmail: !!email,
                ip: req.ip
            });
            return res.status(400).json({
                message: 'Datos de autenticación incompletos.'
            });
        }

        // 5. Validar y sanitizar email
        const validatedEmail = validateEmailQuery(email);

        // 6. Validar datos adicionales
        const validatedAdditionalData = validateAndSanitizeAdditionalData(req.body);

        let user;
        let message = '';
        let status = 200;

        // 7. Buscar usuario por firebase_uid
        let userResult = await client.query(PREPARED_QUERIES.getUserByFirebaseUid, [firebaseUid]);
        user = userResult.rows[0];

        if (!user) {
            // 8. Buscar por email si no se encontró por UID
            userResult = await client.query(PREPARED_QUERIES.getUserByEmail, [validatedEmail]);
            user = userResult.rows[0];

            if (user) {
                // 9. Usuario existe por email, actualizar firebase_uid
                if (!user.firebase_uid || user.firebase_uid !== firebaseUid) {
                    await client.query(PREPARED_QUERIES.updateFirebaseUid, [firebaseUid, user.user_id]);
                    await secureUpsertUserProfile(client, user.user_id, validatedAdditionalData);
                    userResult = await client.query(PREPARED_QUERIES.getUserById, [user.user_id]);
                    user = userResult.rows[0];
                    message = 'Usuario existente actualizado y sesión iniciada.';
                } else {
                    await secureUpsertUserProfile(client, user.user_id, validatedAdditionalData);
                    if (Object.keys(validatedAdditionalData).length > 0) {
                        userResult = await client.query(PREPARED_QUERIES.getUserById, [user.user_id]);
                        user = userResult.rows[0];
                    }
                    message = 'Sesión iniciada exitosamente.';
                }
            } else {
                // 10. Crear nuevo usuario
                const defaultRoleResult = await client.query(PREPARED_QUERIES.getDefaultRole);
                const defaultRoleId = defaultRoleResult.rows[0]?.role_id;

                if (!defaultRoleId) {
                    await client.query('ROLLBACK');
                    console.error("🔴 ERROR de configuración: Rol 'Usuario' no encontrado.");
                    securityLogger.error("Default role 'Usuario' not found", {
                        timestamp: new Date().toISOString()
                    });
                    return res.status(500).json({
                        message: "Error de configuración del servidor."
                    });
                }

                try {
                    const newUserResult = await client.query(PREPARED_QUERIES.insertUser, [
                        firebaseUid,
                        validatedEmail,
                        defaultRoleId
                    ]);
                    const newUserId = newUserResult.rows[0].user_id;
                    await secureUpsertUserProfile(client, newUserId, validatedAdditionalData);
                    userResult = await client.query(PREPARED_QUERIES.getUserById, [newUserId]);
                    user = userResult.rows[0];
                    message = 'Usuario registrado y sesión iniciada exitosamente.';
                    status = 201;
                    securityLogger.info('New user created', {
                        userId: newUserId,
                        email: validatedEmail,
                        ip: req.ip
                    });
                } catch (insertError) {
                    if (insertError.code === '23505') {
                        userResult = await client.query(PREPARED_QUERIES.getUserByEmail, [validatedEmail]);
                        user = userResult.rows[0];
                        if (user) {
                            message = 'Ya existía una cuenta, se ha iniciado sesión automáticamente.';
                        } else {
                            throw insertError;
                        }
                    } else {
                        throw insertError;
                    }
                }
            }
        } else {
            // 11. Usuario encontrado por firebase_uid
            await secureUpsertUserProfile(client, user.user_id, validatedAdditionalData);
            if (Object.keys(validatedAdditionalData).length > 0) {
                userResult = await client.query(PREPARED_QUERIES.getUserById, [user.user_id]);
                user = userResult.rows[0];
            }
            message = 'Sesión iniciada exitosamente.';
        }

        // 12. Verificar si el usuario está bloqueado
        if (user.is_blocked) {
            await client.query('ROLLBACK');
            console.warn('🟡 ADVERTENCIA: Usuario bloqueado intentó iniciar sesión.', 'UserID:', user.user_id, 'Email:', user.email);
            securityLogger.warn('Blocked user attempted login', {
                userId: user.user_id,
                email: user.email,
                ip: req.ip
            });
            return res.status(403).json({
                message: 'Tu cuenta ha sido bloqueada. Por favor, contacta al administrador para más información.'
            });
        }

        // 13. Confirmar transacción
        await client.query('COMMIT');
        const processingTime = Date.now() - startTime;
        securityLogger.info('Successful authentication', {
            userId: user.user_id,
            email: user.email,
            status,
            processingTime,
            ip: req.ip
        });

        // 14. Respuesta exitosa (sin datos sensibles)
        res.status(status).json({
            message: message,
            user: {
                userId: user.user_id,
                firebase_uid: user.firebase_uid,
                email: user.email,
                is_blocked: user.is_blocked,
                role: user.role_name,
                first_name: user.first_name,
                last_name: user.last_name,
                phone: user.phone,
                city: user.city,
                profile_picture_url: user.profile_picture_url,
            }
        });

    } catch (error) {
        if (client) {
            try {
                await client.query('ROLLBACK');
            } catch (rollbackError) {
                console.error('🔴 ERROR al intentar ROLLBACK:', rollbackError.message);
                securityLogger.error('Rollback error', {
                    originalError: error.message,
                    rollbackError: rollbackError.message
                });
            }
        }
        const processingTime = Date.now() - startTime;
        console.error('🔴 ERROR DE AUTENTICACIÓN:', error.message, 'Código:', error.code);
        securityLogger.error('Authentication error', {
            error: error.message,
            code: error.code,
            processingTime,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            hasFirebaseUid: !!firebaseUid,
            hasEmail: !!email
        });

        let errorMessage = 'Error al procesar la autenticación.';
        let statusCode = 500;

        if (error.code === 'auth/id-token-expired') {
            errorMessage = 'El token de sesión ha expirado. Por favor, vuelve a iniciar sesión.';
            statusCode = 401;
        } else if (error.code === 'auth/argument-error' || error.code === 'auth/invalid-id-token') {
            errorMessage = 'Token de sesión inválido.';
            statusCode = 401;
        } else if (error.message === 'Token verification timeout') {
            errorMessage = 'Tiempo de verificación agotado. Intenta nuevamente.';
            statusCode = 408;
        } else if (error.message && error.message.includes('Datos inválidos:')) {
            errorMessage = error.message;
            statusCode = 400;
        } else if (error.code === '23505') {
            errorMessage = 'Error de registro de datos.';
            statusCode = 409;
        } else if (error.code === '23503') {
            errorMessage = 'Error de referencia de datos.';
            statusCode = 400;
        } else if (error.code === '23502') {
            errorMessage = 'Faltan datos requeridos.';
            statusCode = 400;
        } else if (error.message && error.message.includes('Firebase')) {
            errorMessage = 'Error de autenticación Firebase.';
            statusCode = 401;
        }

        res.status(statusCode).json({
            message: errorMessage
        });
    } finally {
        if (client) {
            client.release();
        }
    }
};

/**
 * Obtener perfil de usuario por Firebase UID (versión segura)
 */
const getUserProfileByFirebaseUid = async (req, res) => {
    let client;
    try {
        client = await pool.connect();
        const firebaseUid = req.user?.firebase_uid;

        if (!firebaseUid) {
            console.error('🔴 ERROR en getUserProfileByFirebaseUid: UID no encontrado en la solicitud.');
            securityLogger.warn('Profile request without Firebase UID', {
                ip: req.ip,
                userId: req.user?.userId
            });
            return res.status(401).json({
                message: 'Usuario no autenticado correctamente.'
            });
        }

        const userResult = await client.query(PREPARED_QUERIES.getUserByFirebaseUid, [firebaseUid]);
        const userProfile = userResult.rows[0];

        if (!userProfile) {
            console.error('🔴 ERROR en getUserProfileByFirebaseUid: Perfil no encontrado para el UID.');
            securityLogger.warn('Profile not found after authentication', {
                firebaseUid: firebaseUid.substring(0, 8) + '...',
                ip: req.ip
            });
            return res.status(404).json({
                message: 'Perfil de usuario no encontrado.'
            });
        }

        if (userProfile.is_blocked) {
            console.warn('🟡 ADVERTENCIA: Intento de acceso a perfil por usuario bloqueado.', 'UserID:', userProfile.user_id);
            securityLogger.warn('Blocked user attempted profile access', {
                userId: userProfile.user_id,
                ip: req.ip
            });
            return res.status(403).json({
                message: 'Cuenta bloqueada.'
            });
        }

        res.status(200).json({
            message: 'Perfil de usuario obtenido exitosamente.',
            user: {
                userId: userProfile.user_id,
                firebase_uid: userProfile.firebase_uid,
                email: userProfile.email,
                is_blocked: userProfile.is_blocked,
                role: userProfile.role_name,
                first_name: userProfile.first_name,
                last_name: userProfile.last_name,
                phone: userProfile.phone,
                city: userProfile.city,
                profile_picture_url: userProfile.profile_picture_url,
            }
        });
    } catch (error) {
        console.error('🔴 ERROR en getUserProfileByFirebaseUid:', error.message, 'Código:', error.code);
        securityLogger.error('Error in getUserProfileByFirebaseUid', {
            error: error.message,
            ip: req.ip,
            userId: req.user?.userId
        });
        res.status(500).json({
            message: 'Error interno del servidor al obtener el perfil de usuario.'
        });
    } finally {
        if (client) {
            client.release();
        }
    }
};

/**
 * Actualizar perfil de usuario (versión segura)
 */
const updateUserProfile = async (req, res) => {
    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN');

        const userId = req.user?.userId || req.user?.user_id;

        if (!userId) {
            await client.query('ROLLBACK');
            console.error('🔴 ERROR en updateUserProfile: No se encontró el ID de usuario.');
            return res.status(401).json({ message: 'Usuario no autenticado.' });
        }

        const validatedData = validateAndSanitizeAdditionalData(req.body);

        const userCheck = await client.query(
            'SELECT user_id, is_blocked FROM users WHERE user_id = $1',
            [userId]
        );

        if (!userCheck.rows[0]) {
            await client.query('ROLLBACK');
            console.error('🔴 ERROR en updateUserProfile: Intento de actualización de usuario no existente.', 'UserID:', userId);
            securityLogger.warn('Profile update attempt for non-existent user', {
                userId,
                ip: req.ip
            });
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }

        if (userCheck.rows[0].is_blocked) {
            await client.query('ROLLBACK');
            console.warn('🟡 ADVERTENCIA: Usuario bloqueado intentó actualizar perfil.', 'UserID:', userId);
            securityLogger.warn('Blocked user attempted profile update', {
                userId,
                ip: req.ip
            });
            return res.status(403).json({ message: 'Cuenta bloqueada.' });
        }

        await secureUpsertUserProfile(client, userId, validatedData);

        const updatedUser = await client.query(PREPARED_QUERIES.getUserById, [userId]);

        await client.query('COMMIT');

        securityLogger.info('Profile updated successfully', {
            userId,
            updatedFields: Object.keys(validatedData),
            ip: req.ip
        });

        res.status(200).json({
            message: 'Perfil actualizado exitosamente.',
            user: {
                userId: updatedUser.rows[0].user_id,
                firebase_uid: updatedUser.rows[0].firebase_uid,
                email: updatedUser.rows[0].email,
                is_blocked: updatedUser.rows[0].is_blocked,
                role: updatedUser.rows[0].role_name,
                first_name: updatedUser.rows[0].first_name,
                last_name: updatedUser.rows[0].last_name,
                phone: updatedUser.rows[0].phone,
                city: updatedUser.rows[0].city,
                profile_picture_url: updatedUser.rows[0].profile_picture_url,
            }
        });

    } catch (error) {
        if (client) {
            try {
                await client.query('ROLLBACK');
            } catch (rollbackError) {
                console.error('🔴 ERROR al intentar ROLLBACK en updateUserProfile:', rollbackError.message);
                securityLogger.error('Rollback error in updateUserProfile', {
                    originalError: error.message,
                    rollbackError: rollbackError.message
                });
            }
        }
        console.error('🔴 ERROR en updateUserProfile:', error.message, 'Código:', error.code);
        securityLogger.error('Error in updateUserProfile', {
            error: error.message,
            userId: req.user?.userId,
            ip: req.ip
        });

        let errorMessage = 'Error interno del servidor al actualizar el perfil.';
        let statusCode = 500;

        if (error.message && error.message.includes('Datos inválidos:')) {
            errorMessage = error.message;
            statusCode = 400;
        }

        res.status(statusCode).json({ message: errorMessage });
    } finally {
        if (client) {
            client.release();
        }
    }
};

module.exports = {
    handleFirebaseLogin,
    getUserProfileByFirebaseUid,
    updateUserProfile
};
