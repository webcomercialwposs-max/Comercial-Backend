// controllers/authController.js - VERSIÓN DEBUG TEMPORAL

const admin = require('firebase-admin');
const { pool } = require('../db/db.js');
const { validateUserProfileData, sanitizeAndValidate, validateEmailQuery } = require('../middlewares/validations');
const { securityLogger } = require('../middlewares/security.js');

const handleFirebaseLogin = async (req, res) => {
    const startTime = Date.now();
    let client;
    let email = null;
    let firebaseUid = null;

    // ===== DEBUGGING INTENSIVO =====
    console.log('=== FIREBASE LOGIN DEBUG START ===');
    console.log('1. Request Method:', req.method);
    console.log('2. Request URL:', req.originalUrl);
    console.log('3. Request Headers:', JSON.stringify(req.headers, null, 2));
    console.log('4. Request Body:', JSON.stringify(req.body, null, 2));
    console.log('5. Content-Type:', req.get('Content-Type'));
    console.log('6. User-Agent:', req.get('User-Agent'));
    console.log('7. IP Address:', req.ip);
    console.log('================================');

    try {
        // 1. Verificar que el body existe
        if (!req.body) {
            console.log('ERROR: req.body es undefined o null');
            return res.status(400).json({
                message: 'Body de la solicitud faltante.',
                debug: {
                    hasBody: false,
                    bodyType: typeof req.body
                }
            });
        }

        // 2. Verificar estructura del body
        console.log('Body keys:', Object.keys(req.body));
        console.log('Body values (sin tokens sensibles):', {
            hasIdToken: !!req.body.idToken,
            idTokenType: typeof req.body.idToken,
            idTokenLength: req.body.idToken ? req.body.idToken.length : 0,
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            phone: req.body.phone
        });

        // 3. Extraer y validar idToken
        const { idToken, first_name, last_name, phone } = req.body;

        if (!idToken) {
            console.log('ERROR: idToken faltante en el body');
            securityLogger.warn('Authentication attempt without token in body', {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                bodyKeys: Object.keys(req.body || {})
            });
            return res.status(400).json({
                message: 'Se requiere el token de autenticación de Firebase.',
                debug: {
                    hasIdToken: false,
                    bodyKeys: Object.keys(req.body || {})
                }
            });
        }

        console.log('idToken presente:', {
            type: typeof idToken,
            length: idToken.length,
            starts_with: idToken.substring(0, 20) + '...'
        });

        // 4. Conectar a BD
        console.log('Conectando a base de datos...');
        client = await pool.connect();
        await client.query('BEGIN');
        console.log('Conexión a BD establecida');

        // 5. Verificar token con Firebase
        console.log('Verificando token con Firebase Admin...');
        try {
            const tokenVerificationPromise = admin.auth().verifyIdToken(idToken);
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Token verification timeout')), 10000)
            );
            
            const decodedToken = await Promise.race([tokenVerificationPromise, timeoutPromise]);
            console.log('Token verificado exitosamente:', {
                uid: decodedToken.uid,
                email: decodedToken.email,
                exp: new Date(decodedToken.exp * 1000),
                iat: new Date(decodedToken.iat * 1000),
                aud: decodedToken.aud,
                iss: decodedToken.iss
            });
            
            firebaseUid = decodedToken.uid;
            email = decodedToken.email;

        } catch (tokenError) {
            await client.query('ROLLBACK');
            console.log('ERROR en verificación de token:', {
                message: tokenError.message,
                code: tokenError.code,
                errorCode: tokenError.errorInfo?.code,
                errorMessage: tokenError.errorInfo?.message
            });
            
            securityLogger.error('Token verification failed', {
                error: tokenError.message,
                code: tokenError.code,
                ip: req.ip
            });
            
            return res.status(401).json({
                message: 'Token de Firebase inválido o expirado.',
                debug: {
                    tokenError: tokenError.message,
                    tokenCode: tokenError.code
                }
            });
        }

        // 6. Validaciones adicionales
        if (!firebaseUid || !email) {
            await client.query('ROLLBACK');
            console.log('ERROR: Datos de token incompletos:', { firebaseUid, email });
            return res.status(400).json({ 
                message: 'Datos de autenticación incompletos.',
                debug: {
                    hasFirebaseUid: !!firebaseUid,
                    hasEmail: !!email
                }
            });
        }

        // 7. Continuar con el flujo normal...
        console.log('Validando email...');
        const validatedEmail = validateEmailQuery(email);
        console.log('Email validado:', validatedEmail);

        // 8. Validar datos adicionales
        const validatedAdditionalData = {};
        if (first_name) validatedAdditionalData.first_name = first_name;
        if (last_name) validatedAdditionalData.last_name = last_name;
        if (phone) validatedAdditionalData.phone = phone;

        console.log('Datos adicionales validados:', validatedAdditionalData);

        // 9. Por ahora, solo devolver éxito para confirmar que el token funciona
        await client.query('ROLLBACK'); // No hacer cambios reales aún

        console.log('=== DEBUG: TODO FUNCIONA HASTA AQUÍ ===');
        
        res.status(200).json({
            message: 'DEBUG: Token verificado exitosamente',
            debug: {
                firebaseUid,
                email: validatedEmail,
                additionalData: validatedAdditionalData,
                tokenLength: idToken.length
            }
        });

    } catch (error) {
        if (client) {
            try {
                await client.query('ROLLBACK');
            } catch (rollbackError) {
                console.error('Rollback error:', rollbackError);
            }
        }
        
        console.log('=== ERROR GENERAL ===');
        console.error('Error completo:', error);
        console.log('Error message:', error.message);
        console.log('Error code:', error.code);
        console.log('Error stack:', error.stack);
        console.log('====================');
        
        res.status(500).json({
            message: 'Error interno del servidor',
            debug: {
                error: error.message,
                code: error.code,
                hasFirebaseUid: !!firebaseUid,
                hasEmail: !!email
            }
        });
    } finally {
        if (client) {
            client.release();
        }
        console.log('=== FIREBASE LOGIN DEBUG END ===');
    }
};

module.exports = {
    handleFirebaseLogin,
    // Mantén las otras funciones igual...
};
