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

// --- Middlewares de Depuración y CORS (Orden Importante) ---
// Middleware para loguear cada solicitud entrante
app.use((req, res, next) => {
  console.log('Solicitud entrante para:', req.originalUrl);
  next();
});

// Configuración de CORS para permitir solicitudes desde tu frontend
const corsOptions = {
    origin: 'https://comercial-wposs-ft.vercel.app', // ✅ URL de tu frontend en Vercel
    credentials: true, // ✅ Permite cookies y encabezados de autorización (tokens JWT, etc.)
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
});
