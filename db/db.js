const { Pool } = require('pg'); // Importa el módulo Pool de pg

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Función para probar la conexión a la base de datos
async function testDbConnection() {
    try {
        const client = await pool.connect();
        console.log('¡Conexión exitosa a la base de datos PostgreSQL!');
        client.release(); 
    } catch (err) {
        console.error('Error al conectar a la base de datos:', err.message);
        
    }
}

// Exporta el pool para que otros módulos puedan usarlo para hacer consultas
module.exports = {
    query: (text, params) => pool.query(text, params), // Método simplificado para ejecutar consultas
    pool, // Exporta el pool directamente si se necesita para transacciones u otras operaciones
    testDbConnection // Exporta la función para probar la conexión
};