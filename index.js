require('dotenv').config(); 

const express = require('express');
// Importa tanto 'query' como 'testDbConnection' de tu archivo db.js
const { query, testDbConnection } = require('./db/db');
const bcrypt = require('bcrypt'); // Importa bcrypt para hashear contraseñas
const jwt = require('jsonwebtoken'); // Importa jsonwebtoken (lo usaremos para el login)


const app = express(); 
const PORT = process.env.PORT || 3000; // Puerto del servidor


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Prueba la conexión a la base de datos al iniciar la aplicación
testDbConnection();

// Ruta de ejemplo para verificar que el servidor funciona
app.get('/', (req, res) => {
    res.send('Backend de World POS Solutions funcionando!');
});

// *** RUTA PARA EL REGISTRO DE NUEVOS USUARIOS ***
app.post('/api/auth/register', async (req, res) => {
    // Extrae los datos del cuerpo de la petición
    const { username, password, email, first_name, last_name, identification, phone, address, employment_type_name } = req.body;

    try {
        // 1. Verificar si el nombre de usuario o el correo electrónico ya existen en la base de datos
        const userExists = await query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);
        if (userExists.rows.length > 0) {
            // Si ya existe un usuario con ese nombre o email, devuelve un error 400
            return res.status(400).json({ message: 'El nombre de usuario o el correo electrónico ya están registrados.' });
        }

        // 2. Hashear la contraseña antes de almacenarla en la base de datos para mayor seguridad
        const saltRounds = 10; // Define el número de rondas de sal para bcrypt (un valor común y seguro)
        const passwordHash = await bcrypt.hash(password, saltRounds); // Genera el hash de la contraseña

        // 3. Obtener el role_id para el rol 'empleado' (este será el rol por defecto para nuevos registros)
        const roleResult = await query('SELECT role_id FROM roles WHERE role_name = $1', ['empleado']);
        if (roleResult.rows.length === 0) {
            // Si por alguna razón el rol 'empleado' no existe en la tabla de roles, devuelve un error interno
            return res.status(500).json({ message: 'Error interno: Rol "empleado" no encontrado en la base de datos.' });
        }
        const role_id = roleResult.rows[0].role_id; // Obtiene el ID del rol 'empleado'

        // 4. Insertar el nuevo usuario en la tabla 'users'
        // RETURNING user_id nos permite obtener el ID del usuario recién insertado
        const newUser = await query(
            'INSERT INTO users (username, password_hash, email, role_id) VALUES ($1, $2, $3, $4) RETURNING user_id',
            [username, passwordHash, email, role_id]
        );
        const user_id = newUser.rows[0].user_id; // Almacena el ID del nuevo usuario

        // 5. Obtener el employment_type_id si se proporcionó un nombre de tipo de empleo
        let employment_type_id = null; // Inicializa a null
        if (employment_type_name) { // Si se envió un nombre de tipo de empleo en la petición
            const employmentTypeResult = await query('SELECT employment_type_id FROM employment_types WHERE employment_type_name = $1', [employment_type_name]);
            if (employmentTypeResult.rows.length > 0) {
                // Si el tipo de empleo existe, obtiene su ID
                employment_type_id = employmentTypeResult.rows[0].employment_type_id;
            }
        }

        // 6. Insertar el perfil del usuario en la tabla 'user_profiles'
        await query(
            'INSERT INTO user_profiles (user_id, first_name, last_name, identification, phone, address, employment_type_id) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [user_id, first_name, last_name, identification, phone, address, employment_type_id]
        );

        // Si todo fue exitoso, envía una respuesta de éxito
        res.status(201).json({ message: 'Usuario registrado exitosamente.' });

    } catch (error) {
        // Captura cualquier error que ocurra durante el proceso de registro
        console.error('Error al registrar usuario:', error);
        // Envía una respuesta de error al cliente
        res.status(500).json({ message: 'Error interno del servidor al registrar el usuario.' });
    }
});


// Ruta para el inicio de sesión de usuarios
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body; // Extrae credenciales del cuerpo de la petición

    try {
        // Buscar el usuario por username o email
        const userResult = await query(
            'SELECT user_id, username, password_hash, email, role_id, is_active FROM users WHERE username = $1 OR email = $1',
            [username]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ message: 'Credenciales inválidas.' }); // Usuario no encontrado
        }

        const user = userResult.rows[0];

        // Verificar si el usuario está activo
        if (!user.is_active) {
            return res.status(401).json({ message: 'Tu cuenta está inactiva. Contacta al administrador.' });
        }

        // Comparar la contraseña proporcionada con el hash almacenado usando bcrypt
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);

        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Credenciales inválidas.' }); // Contraseña incorrecta
        }

        // Obtener el nombre del rol para incluirlo en el token
        const roleNameResult = await query('SELECT role_name FROM roles WHERE role_id = $1', [user.role_id]);
        const role_name = roleNameResult.rows.length > 0 ? roleNameResult.rows[0].role_name : 'unknown';

        // Verificar que JWT_SECRET esté configurado en .env
        if (!process.env.JWT_SECRET) {
            console.error('Error: JWT_SECRET no está definido en las variables de entorno.');
            return res.status(500).json({ message: 'Error interno del servidor: clave secreta JWT no configurada.' });
        }

        // Generar un JSON Web Token (JWT) con el ID de usuario, username y rol
        const token = jwt.sign(
            { user_id: user.user_id, username: user.username, role: role_name },
            process.env.JWT_SECRET, // Clave secreta para firmar el token
            { expiresIn: '1h' } // Token expira en 1 hora
        );

        res.status(200).json({ message: 'Inicio de sesión exitoso.', token }); // Respuesta exitosa con el token

    } catch (error) {
        console.error('Error durante el inicio de sesión:', error);
        res.status(500).json({ message: 'Error interno del servidor durante el inicio de sesión.' });
    }
});



// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor escuchando en el puerto ${PORT}`);
});