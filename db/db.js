// db/db.js
const { Pool } = require('pg');
require('dotenv').config();

// Validar que todas las variables de entorno necesarias estén definidas
const requiredEnvVars = ['DB_USER', 'DB_HOST', 'DB_DATABASE', 'DB_PASSWORD', 'DB_PORT'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
    console.error('❌ ERROR: Faltan variables de entorno requeridas para la base de datos:');
    missingVars.forEach(varName => console.error(`   - ${varName}`));
    console.error('\n📝 Crea un archivo .env con las siguientes variables:');
    console.error('   DB_USER=tu_usuario_supabase');
    console.error('   DB_HOST=db.tu_proyecto.supabase.co');
    console.error('   DB_DATABASE=postgres');
    console.error('   DB_PASSWORD=tu_password_supabase');
    console.error('   DB_PORT=5432');
    console.error('\n💡 También puedes usar .env.example como plantilla.');
    process.exit(1);
}

// Configuración del pool de conexiones
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    // Configuraciones adicionales para mejor rendimiento
    max: 20, // máximo número de conexiones en el pool
    idleTimeoutMillis: 30000, // tiempo máximo que una conexión puede estar inactiva
    connectionTimeoutMillis: 2000, // tiempo máximo para establecer una conexión
    ssl: {
        rejectUnauthorized: false // Necesario para Supabase
    }
});

// Eventos del pool
pool.on('connect', () => {
    console.log('✅ Conectado a la base de datos PostgreSQL (Supabase)');
    console.log(`   📍 Host: ${process.env.DB_HOST}`);
    console.log(`   🗄️  Base de datos: ${process.env.DB_DATABASE}`);
    console.log(`   👤 Usuario: ${process.env.DB_USER}`);
});

pool.on('error', (err) => {
    console.error('❌ Error inesperado en la conexión a la base de datos:', err);
    console.error('   🔍 Verifica tu conexión a internet y las credenciales de Supabase');
    process.exit(-1);
});

// Función para probar la conexión
const testConnection = async () => {
    let client;
    try {
        client = await pool.connect();
        const result = await client.query('SELECT NOW() as current_time, version() as db_version');
        console.log('✅ Prueba de conexión exitosa');
        console.log(`   🕐 Hora del servidor: ${result.rows[0].current_time}`);
        console.log(`   🗄️  Versión: ${result.rows[0].db_version.split(' ')[0]}`);
        return true;
    } catch (error) {
        console.error('❌ Error al probar la conexión:', error.message);
        console.error('   🔍 Verifica:');
        console.error('      - Las credenciales en tu archivo .env');
        console.error('      - Que tu proyecto de Supabase esté activo');
        console.error('      - Tu conexión a internet');
        return false;
    } finally {
        if (client) client.release();
    }
};

// Función para cerrar el pool de conexiones
const closePool = async () => {
    try {
        await pool.end();
        console.log('✅ Pool de conexiones cerrado correctamente');
    } catch (error) {
        console.error('❌ Error al cerrar el pool de conexiones:', error.message);
    }
};

module.exports = {
    pool,
    testConnection,
    closePool
};
