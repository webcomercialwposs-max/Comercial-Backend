// index.js (Archivo principal del backend)
require('dotenv').config(); // Carga las variables de entorno desde .env
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const authRoutes = require('./routes/authRoutes.js');
const adminRoutes = require('./routes/adminRoutes.js');
const userRoutes = require('./routes/userRoutes.js');
const db = require('./db/db.js');

// --- INICIALIZACIÓN DE FIREBASE ADMIN SDK ---
const serviceAccount = require('./serviceAccountKey.json'); 
if (!admin.apps.length) { 
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log('Firebase Admin SDK inicializado correctamente en index.js.');
} else {
  console.log('Firebase Admin SDK ya está inicializado (previniendo reinicialización en index.js).');
}

const app = express();
const port = process.env.PORT || 3000;

// --- Middlewares ---
app.use(express.json());
app.use(cors({
  origin: 'https://comercial-wposs-ft.vercel.app',
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
  res.send('API de autenticación está funcionando!');
});

// --- Iniciar el servidor ---
app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
