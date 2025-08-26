const User = require('../models/User'); // Asume que tienes un modelo de usuario
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { getAuth } = require('firebase-admin/auth');

exports.forgotPassword = async (req, res) => {
    // Log al inicio del controlador para verificar el contenido del cuerpo de la solicitud.
    console.log('LOG: authController.forgotPassword: Petición recibida. req.body:', req.body);
    try {
        // Extraemos el email del cuerpo de la solicitud.
        const { email } = req.body;

        // Buscamos al usuario en la base de datos por su email.
        console.log(`LOG: Buscando al usuario con el email: "${email}" en la base de datos.`);
        const user = await User.findOne({ email });
        
        if (!user) {
            // Log si el usuario no se encuentra.
            console.warn(`WARN: authController.forgotPassword: Usuario no encontrado para el email: "${email}".`);
            return res.status(404).json({ message: "Usuario no encontrado." });
        }

        // Aquí iría tu lógica para generar un token y enviar un correo
        // (ejemplo ficticio)
        console.log('LOG: Usuario encontrado. Generando token y enviando email...');

        // Simula el envío de un email
        // await sendPasswordResetEmail(user);

        // Log de éxito.
        console.log('LOG: Proceso de recuperación de contraseña completado exitosamente.');
        res.status(200).json({ message: "El correo para restablecer la contraseña ha sido enviado." });

    } catch (error) {
        // Log detallado de cualquier error que ocurra.
        console.error('FATAL ERROR: authController.forgotPassword: Error en la operación de restablecer contraseña. Detalle:', error);
        res.status(500).json({ message: "Error interno del servidor.", error: error.message });
    }
};

exports.register = async (req, res) => {
    // Log al inicio del controlador para ver los datos validados.
    console.log('LOG: authController.register: Petición recibida. req.body:', req.body);
    try {
        const { first_name, last_name, email, password, phone, city } = req.body;

        // Verificar si el usuario ya existe
        console.log(`LOG: Verificando si ya existe un usuario con el email: "${email}"`);
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            console.warn(`WARN: authController.register: El email "${email}" ya está en uso.`);
            return res.status(400).json({ message: "El correo electrónico ya está registrado." });
        }

        // Hash de la contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Crear nuevo usuario
        const newUser = new User({
            first_name,
            last_name,
            email,
            password: hashedPassword,
            phone,
            city
        });

        // Guardar el usuario en la base de datos
        await newUser.save();
        console.log(`LOG: Nuevo usuario registrado exitosamente: "${email}"`);

        // Generar JWT
        const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({ 
            message: "Registro exitoso", 
            user: {
                id: newUser._id,
                first_name: newUser.first_name,
                email: newUser.email,
            },
            token
        });

    } catch (error) {
        console.error('FATAL ERROR: authController.register: Error al registrar el usuario. Detalle:', error);
        res.status(500).json({ message: "Error interno del servidor.", error: error.message });
    }
};

exports.firebaseLogin = async (req, res) => {
    // Log para confirmar que la ruta ha sido alcanzada y el cuerpo de la solicitud ha sido recibido.
    console.log('LOG: authController.firebaseLogin: Petición recibida.');
    
    // Obtener el token de autenticación del encabezado de la solicitud.
    const idToken = req.headers.authorization?.split('Bearer ')[1];
    
    // Log para verificar si el token está presente.
    console.log('LOG: authController.firebaseLogin: ID Token recibido:', idToken ? 'Sí' : 'No');

    if (!idToken) {
        return res.status(401).json({ message: 'Token no proporcionado.' });
    }

    try {
        // Verificar el token de Firebase.
        const decodedToken = await getAuth().verifyIdToken(idToken);
        const { uid, email, name, picture } = decodedToken;

        // Log para ver el token decodificado y la información del usuario de Firebase.
        console.log('LOG: Token de Firebase decodificado:', { uid, email, name, picture });
        
        // Buscar el usuario en la base de datos usando el UID de Firebase.
        let user = await User.findOne({ firebase_uid: uid });
        let isNewUser = false;

        if (!user) {
            // Si el usuario no existe, lo creamos.
            isNewUser = true;
            console.log('LOG: Usuario no encontrado en la base de datos. Creando nuevo usuario.');
            user = new User({
                firebase_uid: uid,
                email: email,
                first_name: req.body.first_name || name,
                last_name: req.body.last_name,
                profile_picture_url: picture,
                // Agrega otros campos si son necesarios
            });

            // Log de los datos del nuevo usuario a guardar.
            console.log('LOG: Datos del nuevo usuario a guardar:', user);
            await user.save();
            console.log('LOG: Nuevo usuario creado exitosamente.');
        } else {
            console.log('LOG: Usuario existente encontrado en la base de datos.');
        }

        // Generar un token JWT para el usuario.
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        // Enviar una respuesta exitosa.
        console.log('LOG: Proceso de login con Firebase finalizado exitosamente. Enviando respuesta.');
        res.status(200).json({
            message: 'Autenticación con Firebase exitosa.',
            user: {
                _id: user._id,
                email: user.email,
                first_name: user.first_name,
                last_name: user.last_name,
                profile_picture_url: user.profile_picture_url,
                // Agrega otros campos según tu modelo
            },
            token,
            isNewUser
        });

    } catch (error) {
        // Log si hay algún error durante la verificación del token o la operación de base de datos.
        console.error('FATAL ERROR: authController.firebaseLogin: Error al procesar la autenticación. Detalle:', error);
        res.status(500).json({
            message: 'Error al procesar la autenticación.',
            error: error.message
        });
    }
};

