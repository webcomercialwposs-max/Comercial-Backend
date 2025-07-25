// index.js (Archivo principal del backend)
require('dotenv').config(); // Carga las variables de entorno desde .env
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin'); // Importa el paquete 'firebase-admin' directamente aquí
const authRoutes = require('./routes/authRoutes.js'); // Importa tus rutas de autenticación
const adminRoutes = require('./routes/adminRoutes.js'); // Importa tus rutas de administración
const db = require('./db/db.js'); // Asegúrate de que tu pool de PostgreSQL esté importado y conectado

// --- INICIALIZACIÓN DE FIREBASE ADMIN SDK ---
// ¡IMPORTANTE! Reemplaza con la ruta REAL a tu archivo de clave de servicio JSON
// Asegúrate de que el archivo se llame 'serviceAccountKey.json' y esté en la misma carpeta que index.js.
const serviceAccount = require('./serviceAccountKey.json'); 

// Asegúrate de que esta línea se ejecute solo UNA VEZ al iniciar el servidor
if (!admin.apps.length) { 
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log('Firebase Admin SDK inicializado correctamente en index.js.');
} else {
  console.log('Firebase Admin SDK ya está inicializado (previniendo reinicialización en index.js).');
}

const app = express();
const port = process.env.PORT || 3000; // Define el puerto del servidor

// --- Middlewares ---
// Middleware para parsear el cuerpo de las peticiones JSON
app.use(express.json());

// Configura CORS (Cross-Origin Resource Sharing)
app.use(cors());

// --- Rutas de la API ---
// Usar las rutas de autenticación
app.use('/api/auth', authRoutes);

// Usar las rutas de administración
app.use('/api/admin', adminRoutes);

// --- Ruta de prueba básica ---
app.get('/', (req, res) => {
    res.send('API de autenticación está funcionando!');
});

// --- Iniciar el servidor ---
app.listen(port, () => {
    console.log(`Servidor escuchando en http://localhost:${port}`);
});
