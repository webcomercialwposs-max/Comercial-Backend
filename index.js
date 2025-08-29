// index.js (Archivo principal del backend)
require('dotenv').config(); // Carga las variables de entorno desde .env
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const authRoutes = require('./routes/authRoutes.js');
const adminRoutes = require('./routes/adminRoutes.js');
const userRoutes = require('./routes/userRoutes.js');
const { testConnection, closePool } = require('./db/db.js');

// --- INICIALIZACIÓN DE FIREBASE ADMIN SDK ---
const serviceAccount = require('./serviceAccountKey.json'); 
if (!admin.apps.length) { 
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log('✅ Firebase Admin SDK inicializado correctamente en index.js.');
} else {
  console.log('ℹ️  Firebase Admin SDK ya está inicializado (previniendo reinicialización en index.js).');
}

const app = express();
const port = process.env.PORT || 3000;

// --- Middlewares ---
app.use(express.json());
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'https://comercial-wposs-ft.vercel.app',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// --- Rutas de la API ---
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);

// --- Ruta de prueba básica ---
app.get('/', (req, res) => {
  res.json({
    message: 'API de autenticación está funcionando!',
    timestamp: new Date().toISOString(),
    services: {
      firebase: '✅ Inicializado',
      supabase: '🔄 Verificando...'
    }
  });
});

// --- Ruta de estado de la API ---
app.get('/api/status', async (req, res) => {
  try {
    const dbStatus = await testConnection();
    res.json({
      status: 'online',
      timestamp: new Date().toISOString(),
      services: {
        firebase: '✅ Funcionando',
        supabase: dbStatus ? '✅ Conectado' : '❌ Error de conexión',
        database: dbStatus ? '✅ PostgreSQL (Supabase)' : '❌ No disponible'
      },
      environment: {
        node_version: process.version,
        platform: process.platform,
        port: port
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Error al verificar el estado de los servicios',
      error: error.message
    });
  }
});

// --- Manejo de errores global ---
app.use((err, req, res, next) => {
  console.error('❌ Error no manejado:', err);
  res.status(500).json({
    message: 'Error interno del servidor',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Algo salió mal'
  });
});

// --- Manejo de rutas no encontradas ---
app.use('*', (req, res) => {
  res.status(404).json({
    message: 'Ruta no encontrada',
    available_routes: [
      'GET /',
      'GET /api/status',
      'POST /api/auth/login',
      'GET /api/user/profile',
      'PUT /api/user/profile'
    ]
  });
});

// --- Función para iniciar el servidor ---
const startServer = async () => {
  try {
    // Probar conexión a Supabase antes de iniciar
    console.log('🔄 Probando conexión a Supabase...');
    const dbConnected = await testConnection();
    
    if (!dbConnected) {
      console.error('❌ No se pudo conectar a Supabase. El servidor no se iniciará.');
      console.error('   🔍 Verifica tu archivo .env y las credenciales de Supabase.');
      process.exit(1);
    }

    // Iniciar el servidor
    const server = app.listen(port, () => {
      console.log('🚀 Servidor iniciado exitosamente!');
      console.log(`   📍 URL: http://localhost:${port}`);
      console.log(`   🔗 API Status: http://localhost:${port}/api/status`);
      console.log(`   🗄️  Base de datos: Conectado a Supabase`);
      console.log(`   🔥 Firebase: Inicializado`);
    });

    // Manejo de cierre graceful
    process.on('SIGTERM', async () => {
      console.log('🔄 Recibida señal SIGTERM, cerrando servidor...');
      server.close(async () => {
        console.log('✅ Servidor HTTP cerrado');
        await closePool();
        process.exit(0);
      });
    });

    process.on('SIGINT', async () => {
      console.log('🔄 Recibida señal SIGINT, cerrando servidor...');
      server.close(async () => {
        console.log('✅ Servidor HTTP cerrado');
        await closePool();
        process.exit(0);
      });
    });

  } catch (error) {
    console.error('❌ Error al iniciar el servidor:', error);
    process.exit(1);
  }
};

// --- Iniciar el servidor ---
startServer();
