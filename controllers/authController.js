// controllers/authController.js
const pool = require('../db/db.js').pool;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Función para registrar un nuevo usuario y su perfil, y una petición de rol
exports.registerUser = async (req, res) => {
    const { 
        username, 
        password, 
        email, 
        first_name, 
        last_name, 
        identification, 
        phone, 
        address, 
        city, 
        requested_role_name   // Nombre del rol que el usuario SOLICITA
    } = req.body;

    const client = await pool.connect(); // Obtener un cliente del pool para la transacción

    try {
        await client.query('BEGIN'); // Iniciar la transacción

        const hashedPassword = await bcrypt.hash(password, 10);

        // 2. Obtener el role_id para el rol por defecto ('Usuario_Registrado')
        const defaultRoleResult = await client.query(
            'SELECT role_id FROM roles WHERE role_name = $1', 
            ['Usuario_Registrado'] 
        );
        if (defaultRoleResult.rows.length === 0) {
            throw new Error('Rol por defecto "Usuario_Registrado" no encontrado en la base de datos. Por favor, asegúrate de que exista en tu tabla roles.');
        }
        const defaultRoleId = defaultRoleResult.rows[0].role_id;

        // 3. Insertar el usuario en la tabla 'users' con el rol por defecto
        const userInsertResult = await client.query(
            'INSERT INTO users (username, password_hash, email, role_id) VALUES ($1, $2, $3, $4) RETURNING user_id, username, email',
            [username, hashedPassword, email, defaultRoleId]
        );
        const newUser = userInsertResult.rows[0];

        // 4. Definir el ID por defecto para employment_type_id
        // ¡¡¡CAMBIA ESTE VALOR (5) POR EL ID QUE REALMENTE CORRESPONDE A 'Usuario General' en tu tabla employment_types!!!
        const defaultEmploymentTypeId = 5; // Asumiendo que 5 es el ID para 'Usuario General' que insertamos en el SQL

        // 5. Insertar el perfil del usuario en la tabla 'user_profiles' con el ID de tipo de empleo por defecto
        await client.query(
            'INSERT INTO user_profiles (user_id, first_name, last_name, identification, phone, address, city, employment_type_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
            [newUser.user_id, first_name, last_name, identification, phone, address, city, defaultEmploymentTypeId]
        );

        // 6. Si se solicita un rol específico, registrarlo como petición pendiente en 'role_requests'
        if (requested_role_name) {
            const requestedRoleResult = await client.query(
                'SELECT role_id FROM roles WHERE role_name = $1',
                [requested_role_name]
            );
            if (requestedRoleResult.rows.length === 0) {
                throw new Error(`Rol solicitado "${requested_role_name}" no encontrado. Por favor, asegúrate de que exista en tu tabla roles.`);
            }
            const requestedRoleId = requestedRoleResult.rows[0].role_id;

            await client.query(
                'INSERT INTO role_requests (user_id, requested_role_id, status) VALUES ($1, $2, $3)',
                [newUser.user_id, requestedRoleId, 'pending'] // El estado 'pending' (en inglés) es el que cumple la restricción CHECK
            );
        }

        await client.query('COMMIT'); // Confirmar la transacción
        res.status(201).json({ 
            message: 'Usuario, perfil y petición de rol (si aplica) registrados exitosamente.', 
            user: newUser 
        });

    } catch (error) {
        await client.query('ROLLBACK'); // Deshacer la transacción en caso de error
        console.error('Error al registrar usuario completo:', error);
        if (error.code === '23505') { 
            return res.status(409).json({ message: 'El nombre de usuario o correo electrónico ya existe.' });
        }
        res.status(500).json({ message: 'Error interno del servidor al registrar usuario completo: ' + error.message });
    } finally {
        client.release(); // Liberar el cliente de la base de datos
    }
};

// Funciones loginUser y getUserProfile no cambian
exports.loginUser = async (req, res) => {
    const { username, password } = req.body;
    try {
        const userResult = await pool.query('SELECT u.user_id, u.username, u.password_hash, u.email, r.role_name FROM users u JOIN roles r ON u.role_id = r.role_id WHERE u.username = $1', [username]);
        if (userResult.rows.length === 0) {
            return res.status(400).json({ message: 'Credenciales inválidas.' });
        }

        const user = userResult.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).json({ message: 'Credenciales inválidas.' });
        }

        const token = jwt.sign(
            { id: user.user_id, username: user.username, role_name: user.role_name },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: 'Inicio de sesión exitoso.',
            token,
            user: {
                id: user.user_id,
                username: user.username,
                email: user.email,
                role_name: user.role_name
            }
        });
    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
};

exports.getUserProfile = async (req, res) => {
    try {
        const userProfile = await pool.query(
            'SELECT u.user_id, u.username, u.email, r.role_name FROM users u JOIN roles r ON u.role_id = r.role_id WHERE u.user_id = $1',
            [req.user.id]
        );
        if (userProfile.rows.length === 0) {
            return res.status(404).json({ message: 'Perfil de usuario no encontrado.' });
        }
        res.status(200).json({ user: userProfile.rows[0] });
    } catch (error) {
        console.error('Error al obtener perfil del usuario:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
};