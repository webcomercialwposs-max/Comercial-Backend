// db/db.js - CONFIGURACIÓN CORREGIDA PARA SUPABASE
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // ✅ CAMBIO CLAVE: Forzar IPv4 para evitar ENETUNREACH
  family: 4,
  // Configuraciones adicionales para Supabase
  ssl: {
    rejectUnauthorized: false
  },
  // Configuraciones de pool para mejor rendimiento
  max: 20, // máximo número de conexiones en el pool
  idleTimeoutMillis: 30000, // cierra conexiones inactivas después de 30s
  connectionTimeoutMillis: 10000, // timeout de conexión 10s
  acquireTimeoutMillis: 60000, // timeout para obtener una conexión
  // Configuración para reconexión automática
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000,
});

pool.on('connect', (client) => {
  console.log('✅ Conectado a la base de datos PostgreSQL');
  console.log('Cliente conectado:', {
    host: client.host,
    port: client.port,
    database: client.database
  });
});

pool.on('error', (err, client) => {
  console.error('❌ Error inesperado en la conexión a la base de datos:', err);
  
  // Log específico para errores de red
  if (err.code === 'ENETUNREACH') {
    console.error('🚫 Red no alcanzable - problema de conectividad IPv6/IPv4');
  } else if (err.code === 'ECONNREFUSED') {
    console.error('🚫 Conexión rechazada - servidor de BD no disponible');
  } else if (err.code === 'ETIMEDOUT') {
    console.error('⏰ Timeout de conexión - servidor de BD no responde');
  }
  
  // Solo terminar el proceso en errores críticos, no en errores de conexión individuales
  if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
    console.error('💀 Error crítico de base de datos. Terminando proceso...');
    process.exit(-1);
  }
});

// Event listener para cuando se adquiere una conexión del pool
pool.on('acquire', (client) => {
  console.log('🔄 Conexión adquirida del pool');
});

// Event listener para cuando se libera una conexión al pool
pool.on('release', (err, client) => {
  if (err) {
    console.error('⚠️  Error al liberar conexión:', err.message);
  } else {
    console.log('✅ Conexión liberada al pool');
  }
});

// Función para probar la conexión al iniciar
const testConnection = async () => {
  let client;
  try {
    console.log('🔍 Probando conexión a la base de datos...');
    client = await pool.connect();
    const result = await client.query('SELECT NOW()');
    console.log('✅ Conexión exitosa. Hora del servidor:', result.rows[0].now);
    return true;
  } catch (error) {
    console.error('❌ Error en prueba de conexión:', error);
    return false;
  } finally {
    if (client) {
      client.release();
    }
  }
};

// Función para cerrar todas las conexiones del pool (útil para testing)
const closePool = async () => {
  try {
    await pool.end();
    console.log('🔒 Pool de conexiones cerrado');
  } catch (error) {
    console.error('❌ Error cerrando pool:', error);
  }
};

// Manejar cierre graceful de la aplicación
process.on('SIGINT', async () => {
  console.log('🛑 Señal SIGINT recibida. Cerrando pool de conexiones...');
  await closePool();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('🛑 Señal SIGTERM recibida. Cerrando pool de conexiones...');
  await closePool();
  process.exit(0);
});

module.exports = {
  pool,
  testConnection,
  closePool
};
