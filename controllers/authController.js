// controllers/authController.js - VERSIÓN SECURIZADA

const admin = require('firebase-admin');
const { pool } = require('../db/db.js');
const { validateUserProfileData, sanitizeAndValidate, validateEmailQuery } = require('../middlewares/validations');
const { securityLogger } = require('../middlewares/security.js');

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
        WHERE u.email = $1`, // Removido LOWER() innecesario
    
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
        securityLogger.error('Error in secureUpsertUserProfile', {
            userId,
            error: error.message,
            code: error.code
        });
        throw error;
    }
};

/**
 * Función para validar y sanitizar datos de entrada de forma segura
 */
const validateAndSanitizeAdditionalData = (rawData) => {
    if (!rawData || typeof rawData !== 'object') {
        return {};
    }

    const validatedData = {};

    try {
        // Validar cada campo si existe
        if (rawData.first_name !== undefined && rawData.first_name !== null) {
            validatedData.first_name = sanitizeAndValidate.validateName(
                rawData.first_name, 'Nombre'
            );
        }
        
        if (rawData.last_name !== undefined && rawData.last_name !== null) {
            validatedData.last_name = sanitizeAndValidate.validateName(
                rawData.last_name, 'Apellido'
            );
        }
        
        if (rawData.phone !== undefined && rawData.phone !== null) {
            validatedData.phone = sanitizeAndValidate.validatePhone(rawData.phone);
        }
        
        if (rawData.city !== undefined && rawData.city !== null) {
            validatedData.city = sanitizeAndValidate.validateCity(rawData.city);
        }
        
        if (rawData.profile_picture_url !== undefined && rawData.profile_picture_url !== null) {
            validatedData.profile_picture_url = sanitizeAndValidate.validateProfilePictureUrl(
                rawData.profile_picture_url
            );
        }

        return validatedData;
    } catch (error) {
        securityLogger.warn('Data validation failed', {
            error: error.message,
            rawDataKeys: Object.keys(rawData)
        });
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
        if (!idToken || idToken.length < 100) { // Tokens Firebase son largos
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
                    
                    // Recargar datos actualizados
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
                    securityLogger.error("Default role 'Usuario' not found", {
                        timestamp: new Date().toISOString()
                    });
                    return res.status(500).json({ 
                        message: "Error de configuración del servidor." 
                    });
                }
                
                // Insertar usuario con manejo de concurrencia
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
                        // Race condition - el usuario ya fue creado
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
        // Rollback en caso de error
        if (client) {
            try {
                await client.query('ROLLBACK');
            } catch (rollbackError) {
                securityLogger.error('Rollback error', {
                    originalError: error.message,
                    rollbackError: rollbackError.message
                });
            }
        }
        
        const processingTime = Date.now() - startTime;
        
        // Log detallado del error (sin datos sensibles)
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

        // Manejo específico de errores
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
            // Error de duplicidad ya manejado arriba, pero por seguridad
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

        res.status(statusCode).json({ message: errorMessage });
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
            securityLogger.warn('Profile not found after authentication', {
                firebaseUid: firebaseUid.substring(0, 8) + '...', // Log parcial por seguridad
                ip: req.ip
            });
            return res.status(404).json({ 
                message: 'Perfil de usuario no encontrado.' 
            });
        }

        if (userProfile.is_blocked) {
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
            return res.status(401).json({ message: 'Usuario no autenticado.' });
        }

        // Validar datos de entrada
        const validatedData = validateAndSanitizeAdditionalData(req.body);

        // Verificar que el usuario existe y no está bloqueado
        const userCheck = await client.query(
            'SELECT user_id, is_blocked FROM users WHERE user_id = $1',
            [userId]
        );

        if (!userCheck.rows[0]) {
            await client.query('ROLLBACK');
            securityLogger.warn('Profile update attempt for non-existent user', {
                userId,
                ip: req.ip
            });
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }

        if (userCheck.rows[0].is_blocked) {
            await client.query('ROLLBACK');
            securityLogger.warn('Blocked user attempted profile update', {
                userId,
                ip: req.ip
            });
            return res.status(403).json({ message: 'Cuenta bloqueada.' });
        }

        // Actualizar perfil con datos validados
        await secureUpsertUserProfile(client, userId, validatedData);

        // Obtener datos actualizados
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
                securityLogger.error('Rollback error in updateUserProfile', {
                    originalError: error.message,
                    rollbackError: rollbackError.message
                });
            }
        }
        
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