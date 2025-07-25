// deleteFirebaseUsers.js
// Script para eliminar todos los usuarios de Firebase Authentication programáticamente.

// Carga las variables de entorno del archivo .env
require('dotenv').config();

const admin = require('firebase-admin');
const path = require('path'); // Módulo 'path' para resolver rutas de forma segura

// **********************************************************************************
// IMPORTANTE:
// Asegúrate de que tu archivo .env en la raíz de la carpeta 'Backend'
// contenga la siguiente línea con la ruta correcta a tu archivo JSON de clave de servicio:
//
// FIREBASE_SERVICE_ACCOUNT_KEY_PATH='./web-comercial-38892-firebase-adminsdk-fbsvc-3b03c22d6b.json'
//
// (Ajusta el nombre del archivo si es diferente).
// **********************************************************************************

const serviceAccountFileName = process.env.FIREBASE_SERVICE_ACCOUNT_KEY_PATH;

if (!serviceAccountFileName) {
  console.error('ERROR: La variable de entorno FIREBASE_SERVICE_ACCOUNT_KEY_PATH no está definida en tu archivo .env');
  console.error('Asegúrate de que tu .env contenga: FIREBASE_SERVICE_ACCOUNT_KEY_PATH=\'./nombre-de-tu-archivo.json\'');
  process.exit(1);
}

// Resuelve la ruta completa al archivo de clave de servicio.
// Esto asume que el script se ejecuta desde la raíz de la carpeta 'Backend'
// y que el archivo .env contiene una ruta relativa a esa misma carpeta.
const serviceAccountPath = path.resolve(__dirname, serviceAccountFileName);

try {
  // Intentar cargar el archivo JSON de la clave de servicio
  const serviceAccount = require(serviceAccountPath);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });

  console.log('Firebase Admin SDK inicializado para eliminación de usuarios.');

} catch (error) {
  console.error('ERROR: No se pudo inicializar Firebase Admin SDK.');
  console.error('Causa:', error.message);
  console.error(`Asegúrate de que la ruta '${serviceAccountPath}' sea correcta y el archivo JSON exista y sea válido.`);
  console.error('Verifica la variable FIREBASE_SERVICE_ACCOUNT_KEY_PATH en tu archivo .env.');
  process.exit(1); // Salir si no se puede inicializar
}

const deleteUsers = async () => {
  let nextPageToken;
  let usersDeletedCount = 0;

  console.log('Iniciando eliminación de todos los usuarios de Firebase Authentication...');

  try {
    do {
      // Obtener hasta 1000 usuarios por vez
      const listUsersResult = await admin.auth().listUsers(1000, nextPageToken);
      const uidsToDelete = listUsersResult.users.map(userRecord => userRecord.uid);

      if (uidsToDelete.length > 0) {
        console.log(`Eliminando ${uidsToDelete.length} usuarios...`);
        // Eliminar los usuarios en un lote
        await admin.auth().deleteUsers(uidsToDelete);
        usersDeletedCount += uidsToDelete.length;
        console.log(`Eliminados ${usersDeletedCount} usuarios hasta ahora.`);
      }

      // Obtener el token para la siguiente página de usuarios, si existe
      nextPageToken = listUsersResult.pageToken;

    } while (nextPageToken); // Continuar mientras haya más páginas de usuarios

    console.log(`¡Proceso completado! Total de usuarios eliminados: ${usersDeletedCount}`);

  } catch (error) {
    console.error('Error durante la eliminación de usuarios:', error);
  } finally {
    // Opcional: Descomentar si quieres cerrar la aplicación de admin después de la ejecución.
    // admin.app().delete();
  }
};

// Ejecutar la función para eliminar usuarios
deleteUsers();
