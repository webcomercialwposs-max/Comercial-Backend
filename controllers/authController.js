const User = require('../models/User'); // Asume que tienes un modelo de usuario
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

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

// ... (otros exports de tu controlador)
