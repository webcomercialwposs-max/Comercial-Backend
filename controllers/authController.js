const handleFirebaseLogin = async (req, res) => {
    const startTime = Date.now();
    let client;
    let email = null;
    let firebaseUid = null;

    try {
        // ... (Tu código para obtener el idToken de los headers)

        const idToken = authHeader.split(' ')[1];

        // Validación básica del token
        if (!idToken || idToken.length < 100) {
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

        // ¡ATENCIÓN AQUÍ! Envolvemos la verificación en un bloque try...catch para un log más específico
        let decodedToken;
        try {
            decodedToken = await Promise.race([tokenVerificationPromise, timeoutPromise]);
        } catch (verificationError) {
            // AÑADIDO: Log específico del error de verificación
            console.error('🔴 ERROR DE VERIFICACIÓN DE TOKEN:', verificationError.message, verificationError.code);
            throw verificationError; // Relanzamos el error para que el bloque catch principal lo maneje
        }

        firebaseUid = decodedToken.uid;
        email = decodedToken.email;

        // ... (El resto de tu código para buscar/crear usuario, etc.)

        // 13. Confirmar transacción
        await client.query('COMMIT');

        // ... (Tu código para la respuesta exitosa)

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

        // ... (Tu código para el manejo específico de errores)

        res.status(statusCode).json({
            message: errorMessage
        });
    } finally {
        if (client) {
            client.release();
        }
    }
};
