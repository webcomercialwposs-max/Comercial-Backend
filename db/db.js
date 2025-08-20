// db/db.js
const { Pool } = require('pg');

// Si existe la variable DATABASE_URL, úsala. De lo contrario, usa las variables locales.
const connectionString = process.env.DATABASE_URL || {
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
};

const pool = new Pool({
    connectionString,
    ssl: {
        rejectUnauthorized: false, // Necesario para algunas configuraciones de bases de datos
    },
});

pool.on('connect', () => {
    console.log('Conectado a la base de datos PostgreSQL');
});

pool.on('error', (err) => {
    console.error('Error inesperado en la conexión a la base de datos', err);
    process.exit(-1);
});

module.exports = {
    pool,
};
