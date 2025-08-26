// index.js (Archivo principal del backend)
require('dotenv').config(); // Carga las variables de entorno desde .env
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

// Importa las rutas
const authRoutes = require('./routes/authRoutes.js');
const adminRoutes = require('./routes/adminRoutes.js');
const userRoutes = require('./routes/userRoutes.js');

// Importa la conexión a la base de datos (si es necesario aquí)
// const db = require('./db/db.js');

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
// Esto permite que Express confíe en la información de IP que le envía el proxy (Render).
app.set('trust proxy', 1);


// --- MIDDLEWARES (EL ORDEN ES MUY IMPORTANTE) ---

// 1. Configuración de CORS para permitir solicitudes desde tu frontend
const corsOptions = {
    origin: 'https://comercial-wposs-ft.vercel.app', // URL de tu frontend en Vercel
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// 2. Middleware para parsear el cuerpo de las solicitudes en formato JSON
// !! ESTA ES LA CORRECCIÓN PRINCIPAL. Debe ir ANTES de cualquier ruta o middleware que lea req.body !!
app.use(express.json());

// 3. Middleware de depuración para inspeccionar cada solicitud
// Ahora que express.json() se ejecutó antes, req.body ya no será 'undefined'
app.use((req, res, next) => {
    console.log('-----------------------------------');
    console.log('🔍 LOG DE SOLICITUD ENTRANTE');
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    console.log('IP del Cliente (detectada por Express):', req.ip);
    console.log('Encabezados (Headers):', req.headers);
    console.log('Cuerpo (Body):', req.body); // <-- ¡Ahora sí tendrá contenido!
    console.log('Parámetros de URL (Query):', req.query);
    console.log('-----------------------------------');
    next();
});


// --- RUTAS DE LA API ---
// Las rutas se definen DESPUÉS de todos los middlewares de configuración
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);


// --- RUTA DE PRUEBA BÁSICA ---
app.get('/', (req, res) => {
  res.send('API de autenticación está funcionando!');
});


// --- MANEJO DE ERRORES (al final de todas las rutas) ---

// Manejo de rutas no encontradas (404)
app.use('*', (req, res) => {
  res.status(404).json({
    message: 'Ruta no encontrada',
    requestedUrl: req.originalUrl
  });
});

// Manejo de errores globales (debe tener 4 argumentos)
app.use((error, req, res, next) => {
  console.error('Error global capturado:', error.message);
  console.error('Stack trace:', error.stack);
  
  res.status(500).json({
    message: 'Error interno del servidor',
    // Solo muestra el mensaje de error detallado en desarrollo
    ...(process.env.NODE_ENV === 'development' && { error: error.message })
  });
});


// --- MANEJO DE ERRORES NO CAPTURADOS (A nivel de proceso) ---
process.on('unhandledRejection', (err) => {
  console.error('Unhandled Promise Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});


// --- INICIAR EL SERVIDOR ---
app.listen(port, () => {
  console.log(`==> Your service is live 🎉`);
  console.log(`==> `);
  console.log(`==> ///////////////////////////////////////////////////////////`);
  console.log(`==> `);
  console.log(`==> Available at your primary URL http://localhost:${port}`);
  console.log(`==> `);
  console.log(`==> ///////////////////////////////////////////////////////////`);
  console.log(`Modo: ${process.env.NODE_ENV || 'development'}`);
});
