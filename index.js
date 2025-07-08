require('dotenv').config(); 

const express = require('express');
const { query, testDbConnection } = require('./db/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { authenticateToken, authorizeRoles } = require('./middlewares/authMiddlewares'); // Asegúrate de que esta ruta sea correcta

const app = express(); 
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

testDbConnection();

app.get('/', (req, res) => {
    res.send('Backend de World POS Solutions funcionando!');
});






// --- ÚNICA DEFINICIÓN DE LA RUTA DE REGISTRO ---
app.post('/api/auth/register', async (req, res) => {
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
        employment_type_name
    } = req.body;

    try {
        const userExists = await query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ message: 'El nombre de usuario o el correo electrónico ya están registrados.' });
        }

        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        const defaultRoleResult = await query('SELECT role_id FROM roles WHERE role_name = $1', ['Usuario_Registrado']);
        if (defaultRoleResult.rows.length === 0) {
            console.error('Error de Configuración: El rol "Usuario_Registrado" no existe en la tabla de roles.');
            return res.status(500).json({ message: 'Error interno del servidor: Rol por defecto no configurado.' });
        }
        const default_role_id = defaultRoleResult.rows[0].role_id;

        const newUserResult = await query(
            'INSERT INTO users (username, password_hash, email, role_id) VALUES ($1, $2, $3, $4) RETURNING user_id',
            [username, passwordHash, email, default_role_id]
        );
        const user_id = newUserResult.rows[0].user_id;

        let employment_type_id_for_profile = null;
        let requested_role_id_for_request = null;

        if (employment_type_name) {
            const employmentTypeResult = await query('SELECT employment_type_id FROM employment_types WHERE employment_type_name = $1', [employment_type_name]);

            if (employmentTypeResult.rows.length > 0) {
                employment_type_id_for_profile = employmentTypeResult.rows[0].employment_type_id;

                const requestedRoleResult = await query('SELECT role_id FROM roles WHERE role_name = $1', [employment_type_name]);

                if (requestedRoleResult.rows.length > 0) {
                    requested_role_id_for_request = requestedRoleResult.rows[0].role_id;

                    await query(
                        'INSERT INTO role_requests (user_id, requested_role_id, status) VALUES ($1, $2, $3)',
                        [user_id, requested_role_id_for_request, 'pendiente']
                    );
                    console.log(`Solicitud de rol '${employment_type_name}' creada para el usuario ${user_id}.`);
                } else {
                    console.warn(`Advertencia: El rol funcional para '${employment_type_name}' no existe en la tabla 'roles'. No se pudo crear la solicitud de rol funcional.`);
                }
            } else {
                console.warn(`Advertencia: El tipo de empleo '${employment_type_name}' declarado por el usuario no existe en la tabla 'employment_types'.`);
            }
        }

        await query(
            'INSERT INTO user_profiles (user_id, first_name, last_name, identification, phone, address, city, employment_type_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
            [user_id, first_name, last_name, identification, phone, address, city, employment_type_id_for_profile]
        );

        res.status(201).json({
            message: 'Usuario registrado exitosamente. Tu cuenta tiene acceso básico. La solicitud de rol está pendiente de revisión.',
            userId: user_id
        });

    } catch (error) {
        console.error('Error al registrar usuario:', error);
        if (error.code === '23505') {
            let detail = 'Error de datos duplicados.';
            if (error.detail.includes('identification')) {
                detail = 'El número de identificación ya está registrado.';
            }
            return res.status(400).json({ message: detail });
        }
        res.status(500).json({ message: 'Error interno del servidor al registrar el usuario.' });
    }
});





// --- ÚNICA DEFINICIÓN DE LA RUTA DE LOGIN ---
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const userResult = await query(
            'SELECT user_id, username, password_hash, email, role_id, is_active FROM users WHERE username = $1 OR email = $1',
            [username]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ message: 'Credenciales inválidas.' });
        }

        const user = userResult.rows[0];

        if (!user.is_active) {
            return res.status(401).json({ message: 'Tu cuenta está inactiva. Contacta al administrador.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Credenciales inválidas.' });
        }

        const roleNameResult = await query('SELECT role_name FROM roles WHERE role_id = $1', [user.role_id]);
        const role_name = roleNameResult.rows.length > 0 ? roleNameResult.rows[0].role_name : 'unknown';

        if (!process.env.JWT_SECRET) {
            console.error('Error: JWT_SECRET no está definido en las variables de entorno.');
            return res.status(500).json({ message: 'Error interno del servidor: clave secreta JWT no configurada.' });
        }

        const token = jwt.sign(
            { user_id: user.user_id, username: user.username, role: role_name },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({ message: 'Inicio de sesión exitoso.', token });

    } catch (error) {
        console.error('Error durante el inicio de sesión:', error);
        res.status(500).json({ message: 'Error interno del servidor durante el inicio de sesión.' });
    }
});





// --- RUTAS PROTEGIDAS CON MIDDLEWARE (estas están bien) ---
app.get('/api/protected', authenticateToken, (req, res) => {
    res.status(200).json({
        message: 'Acceso concedido a ruta protegida!',
        user: {
            id: req.user.user_id,
            username: req.user.username,
            role: req.user.role
        }
    });
});

app.get('/api/admin-only', authenticateToken, authorizeRoles(['Administrador']), (req, res) => {
    res.status(200).json({
        message: 'Acceso concedido a ruta solo para Administradores!',
        user: {
            id: req.user.user_id,
            username: req.user.username,
            role: req.user.role
        }
    });
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor escuchando en el puerto ${PORT}`);
});