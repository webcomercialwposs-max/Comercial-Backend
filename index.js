// index.js (Archivo principal del backend)
require('dotenv').config(); // Carga las variables de entorno desde .env
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

// Importa las rutas
const authRoutes = require('./routes/authRoutes.js');
const adminRoutes = require('./routes/adminRoutes.js');
const userRoutes = require('./routes/userRoutes.js');

// Importa la conexión a la base de datos
const db = require('./db/db.js');

// --- INICIALIZACIÓN DE FIREBASE ADMIN SDK ---
try {
  // Para producción (Render): usa la clave completa como string desde la variable de entorno
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log('Firebase Admin SDK inicializado para producción.');
  } else {
    // Para desarrollo local: usa el archivo local
    const serviceAccount = require('./serviceAccountKey.json');
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log('Firebase Admin SDK inicializado para desarrollo.');
  }
} catch (error) {
  console.error('Error FATAL al inicializar Firebase Admin SDK:', error.message);
  process.exit(1);
}

const app = express();
const port = process.env.PORT || 3000;

// ✅ CONFIGURACIÓN CRÍTICA PARA PROXIES (RENDER, HEROKU, ETC.)
app.set('trust proxy', 1);

// Middleware de depuración para inspeccionar el objeto de solicitud (req)
// Coloca esto lo más alto posible en tu archivo index.js, después de app = express()
app.use((req, res, next) => {
    // Intenta loguear req.url de forma segura
    let requestUrl = null;
    try {
        requestUrl = req.url ? new URL(`http://dummy.com${req.url}`) : 'URL NO DEFINIDA';
    } catch (e) {
        requestUrl = `Error al parsear URL: ${e.message}`;
    }

    console.log('-----------------------------------');
    console.log('🔍 LOG DE SOLICITUD ENTRANTE');
    console.log('Método:', req.method);
    console.log('URL Completa (originalUrl):', req.originalUrl);
    console.log('Objeto URL (req.url):', req.url); // Muestra si req.url existe o es undefined
    console.log('Objeto URL Parseado:', requestUrl);
    console.log('Encabezados (Headers):', req.headers);
    console.log('Cuerpo (Body):', req.body);
    console.log('Parámetros de URL (Query):', req.query);
    console.log('IP del Cliente:', req.ip);
    console.log('-----------------------------------');
    next();
});

// --- Middlewares de Depuración y CORS (Orden Importante) ---
// Middleware para loguear cada solicitud entrante
app.use((req, res, next) => {
  console.log('Solicitud entrante para:', req.originalUrl);
  console.log('IP del cliente:', req.ip || 'no disponible');
  next();
});

// Configuración de CORS para permitir solicitudes desde tu frontend
const corsOptions = {
    origin: 'https://comercial-wposs-ft.vercel.app', // URL de tu frontend en Vercel
    credentials: true, // Permite cookies y encabezados de autorización (tokens JWT, etc.)
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Middleware para parsear el cuerpo de las solicitudes en formato JSON
app.use(express.json());

// --- Rutas de la API ---
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);

// --- Ruta de prueba básica ---
app.get('/', (req, res) => {
  res.send('API de autenticación está funcionando!');
});

// --- Manejo de errores globales ---
app.use((error, req, res, next) => {
  console.error('Error global capturado:', error.message);
  console.error('Stack trace:', error.stack);
  
  res.status(500).json({
    message: 'Error interno del servidor',
    ...(process.env.NODE_ENV === 'development' && { error: error.message })
  });
});

// --- Manejo de rutas no encontradas ---
app.use('*', (req, res) => {
  res.status(404).json({
    message: 'Ruta no encontrada',
    requestedUrl: req.originalUrl
  });
});

// --- Manejo de errores no capturados ---
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

// --- Iniciar el servidor ---
app.listen(port, '0.0.0.0', () => {
  console.log(`Servidor escuchando en puerto ${port}`);
  console.log(`Modo: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Trust proxy configurado: ${app.get('trust proxy')}`);
});
