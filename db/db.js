// db/db.js
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE, // Se tomará de .env
    password: process.env.DB_PASSWORD, // Se tomará de .env
    port: process.env.DB_PORT,         // Se tomará de .env
});

pool.on('connect', () => {
    console.log('Conectado a la base de datos PostgreSQL');
});

pool.on('error', (err) => {
    console.error('Error inesperado en la conexión a la base de datos', err);
    process.exit(-1); // Terminar el proceso si hay un error crítico de DB
});

module.exports = {
    pool,
};
