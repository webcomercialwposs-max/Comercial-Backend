// index.js (Archivo principal del backend)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

// 💡 Nuevo: Importa el archivo de conexión a la DB
// Si ya lo tenías, asegúrate de que esté descomentado
const db = require('./db/db.js');

// 💡 Nuevo: Importa las rutas
const authRoutes = require('./routes/authRoutes.js');
const adminRoutes = require('./routes/adminRoutes.js');
const userRoutes = require('./routes/userRoutes.js');

// --- INICIALIZACIÓN DE FIREBASE ADMIN SDK ---
try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    // 💡 Corrección: Es una buena práctica validar que la cadena no esté vacía
    if (process.env.FIREBASE_SERVICE_ACCOUNT.trim() === '') {
        throw new Error('La variable de entorno FIREBASE_SERVICE_ACCOUNT está vacía.');
    }
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log('Firebase Admin SDK inicializado para producción.');
  } else {
    // 💡 Si no está en producción, es mejor que falle si no encuentra la clave
    throw new Error('FIREBASE_SERVICE_ACCOUNT no está configurada. ¿Estás en producción?');
  }
} catch (error) {
  console.error('Error FATAL al inicializar Firebase Admin SDK:', error.message);
  process.exit(1);
}

const app = express();
const port = process.env.PORT || 3000;

app.set('trust proxy', 1);

// --- MIDDLEWARES (EL ORDEN ES MUY IMPORTANTE) ---
const corsOptions = {
    origin: 'https://comercial-wposs-ft.vercel.app',
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// El middleware para parsear JSON debe ir antes de las rutas.
app.use(express.json());

// 💡 Nuevo: Middleware de logs. Puedes ajustarlo o eliminarlo según tus necesidades.
app.use((req, res, next) => {
    console.log('-----------------------------------');
    console.log('🔍 LOG DE SOLICITUD ENTRANTE');
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    console.log('Cuerpo (Body):', req.body);
    console.log('-----------------------------------');
    next();
});

// --- RUTAS DE LA API ---
// Usa el nuevo archivo de rutas de autenticación
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);


// --- MANEJO DE ERRORES (al final de todas las rutas) ---
app.use('*', (req, res) => {
    res.status(404).json({
        message: 'Ruta no encontrada',
        requestedUrl: req.originalUrl
    });
});

app.use((error, req, res, next) => {
    console.error('Error global capturado:', error.message);
    console.error('Stack trace:', error.stack);

    res.status(500).json({
        message: 'Error interno del servidor',
        ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
});


// --- INICIAR EL SERVIDOR ---
const server = app.listen(port, () => {
    console.log(`==> Your service is live 🎉`);
    console.log(`==> Available at your primary URL http://localhost:${port}`);
    console.log(`Modo: ${process.env.NODE_ENV || 'development'}`);
});

// Manejo de cierres forzados para cerrar la conexión de la DB
process.on('SIGINT', () => {
    server.close(() => {
        console.log('Servidor Express cerrado. Cerrando pool de DB...');
        db.pool.end(() => {
            console.log('Pool de base de datos cerrado.');
            process.exit(0);
        });
    });
});
