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
        securityLogger.info('Received authentication request', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            authHeaderPresent: !!authHeader
        });
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
        securityLogger.info('Extracted ID token', {
            tokenLength: idToken.length,
            ip: req.ip
        });
        
        // Validación básica del token
        if (!idToken || idToken.length < 100) { // Tokens Firebase son largos
            securityLogger.warn('Invalid token length', {
                tokenLength: idToken.length,
                ip: req.ip
            });
            return res.status(401).json({ 
                message: 'Token de autenticación inválido.' 
            });
        }

        // 2. Conectar a BD y comenzar transacción
        client = await pool.connect();
        await client.query('BEGIN');
        securityLogger.info('Database connection established and transaction started', {
            ip: req.ip
        });
        
        // 3. Verificar token con Firebase (con timeout)
        const tokenVerificationPromise = admin.auth().verifyIdToken(idToken);
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Token verification timeout')), 10000)
        );
        
        const decodedToken = await Promise.race([tokenVerificationPromise, timeoutPromise]);
        securityLogger.info('Token verified successfully', {
            firebaseUid: decodedToken.uid,
            email: decodedToken.email,
            ip: req.ip
        });
        
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
        securityLogger.info('Email validated', {
            originalEmail: email,
            validatedEmail: validatedEmail,
            ip: req.ip
        });
        
        // 6. Validar datos adicionales
        securityLogger.info('Received request body', {
            body: req.body,
            ip: req.ip
        });
        const validatedAdditionalData = validateAndSanitizeAdditionalData(req.body);
        securityLogger.info('Validated additional data', {
            validatedData: validatedAdditionalData,
            ip: req.ip
        });

        let user;
        let message = '';
        let status = 200;

        // 7. Buscar usuario por firebase_uid
        let userResult = await client.query(PREPARED_QUERIES.getUserByFirebaseUid, [firebaseUid]);
        securityLogger.info('Query result for firebase_uid', {
            firebaseUid: firebaseUid,
            rowsCount: userResult.rows.length,
            ip: req.ip
        });
        user = userResult.rows[0];

        if (!user) {
            // 8. Buscar por email si no se encontró por UID
            userResult = await client.query(PREPARED_QUERIES.getUserByEmail, [validatedEmail]);
            securityLogger.info('Query result for email', {
                email: validatedEmail,
                rowsCount: userResult.rows.length,
                ip: req.ip
            });
            user = userResult.rows[0];

            if (user) {
                // 9. Usuario existe por email, actualizar firebase_uid
                if (!user.firebase_uid || user.firebase_uid !== firebaseUid) {
                    await client.query(PREPARED_QUERIES.updateFirebaseUid, [firebaseUid, user.user_id]);
                    securityLogger.info('Updated firebase_uid', {
                        userId: user.user_id,
                        oldFirebaseUid: user.firebase_uid,
                        newFirebaseUid: firebaseUid,
                        ip: req.ip
                    });
                    
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
                securityLogger.info('Queried default role', {
                    rowsCount: defaultRoleResult.rows.length,
                    ip: req.ip
                });
                const defaultRoleId = defaultRoleResult.rows[0]?.role_id;

                if (!defaultRoleId) {
                    await client.query('ROLLBACK');
                    securityLogger.error("Default role 'Usuario' not found", {
                        timestamp: new Date().toISOString(),
                        ip: req.ip
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
                    securityLogger.info('New user inserted', {
                        userId: newUserResult.rows[0].user_id,
                        email: validatedEmail,
                        ip: req.ip
                    });
                    
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
                        securityLogger.warn('Race condition: User already exists', {
                            email: validatedEmail,
                            ip: req.ip
                        });
                        
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
            securityLogger.info('User profile upserted', {
                userId: user.user_id,
                updatedFields: Object.keys(validatedAdditionalData),
                ip: req.ip
            });
            
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
        securityLogger.info('Transaction committed successfully', {
            userId: user.user_id,
            email: user.email,
            ip: req.ip
        });

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
                securityLogger.warn('Transaction rolled back', {
                    error: error.message,
                    ip: req.ip
                });
            } catch (rollbackError) {
                securityLogger.error('Rollback error', {
                    originalError: error.message,
                    rollbackError: rollbackError.message,
                    ip: req.ip
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
            securityLogger.info('Database client released', {
                ip: req.ip
            });
        }
    }
};
