require('dotenv').config();
const express = require('express');
const authRoutes = require('./routes/authRoutes.js');
const adminRoutes = require('./routes/adminRoutes.js'); // Esta línea ya la añadimos

const app = express();
const port = process.env.PORT || 3000;

// Middleware para parsear JSON
app.use(express.json());

// Usar las rutas de autenticación
app.use('/api/auth', authRoutes);

// Usar las rutas de administración (¡Añade esta línea!)
app.use('/api/admin', adminRoutes);

// Ruta de prueba
app.get('/', (req, res) => {
    res.send('API de autenticación está funcionando!');
});

// Iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor escuchando en http://localhost:${port}`);
});