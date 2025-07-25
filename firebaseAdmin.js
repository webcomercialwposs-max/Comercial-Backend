// backend/firebaseAdmin.js
// Este archivo ahora solo exporta la instancia de Firebase Admin SDK
// que ya fue inicializada en index.js.

const admin = require('firebase-admin');

// Opcional: Puedes añadir una verificación para asegurarte de que ya está inicializado.
// Si no lo está, significa un problema en el orden de carga o en index.js.
if (!admin.apps.length) {
    console.warn('ADVERTENCIA: Firebase Admin SDK no está inicializado cuando se importa firebaseAdmin.js. Asegúrate de que index.js lo inicialice primero.');
}

module.exports = admin; // Exporta la instancia de admin ya inicializada
