// deleteFirebaseUsers.js
// Un script para eliminar de manera segura y programática todos los usuarios de Firebase Authentication.
// Ejecutar este script borrará de forma PERMANENTE todos los usuarios de tu proyecto.

// Carga las variables de entorno desde el archivo .env
require('dotenv').config();

const admin = require('firebase-admin');
const path = require('path');

// ======================================================================
// CONFIGURACIÓN:
// Asegúrate de que la variable de entorno esté configurada en tu archivo .env
// con la ruta correcta a tu archivo JSON de clave de servicio.
// Ejemplo: FIREBASE_SERVICE_ACCOUNT_KEY_PATH='nombre-de-tu-archivo.json'
// ======================================================================
const serviceAccountFileName = process.env.FIREBASE_SERVICE_ACCOUNT_KEY_PATH;

if (!serviceAccountFileName) {
  console.error('ERROR: La variable de entorno FIREBASE_SERVICE_ACCOUNT_KEY_PATH no está definida.');
  console.error('Por favor, configúrala en tu archivo .env.');
  process.exit(1);
}

// Resuelve la ruta completa al archivo de clave de servicio usando path.join.
// Esto es más seguro y fiable que la concatenación de cadenas.
const serviceAccountPath = path.join(__dirname, serviceAccountFileName);

// Inicializa Firebase Admin SDK. Este paso verifica que la ruta del archivo sea correcta.
try {
  const serviceAccount = require(serviceAccountPath);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });

  console.log('Firebase Admin SDK inicializado correctamente.');

} catch (error) {
  console.error('ERROR: No se pudo inicializar Firebase Admin SDK.');
  console.error(`Causa: ${error.message}`);
  console.error(`Asegúrate de que la ruta '${serviceAccountPath}' sea correcta y el archivo exista.`);
  process.exit(1);
}

/**
 * Función principal para eliminar todos los usuarios de Firebase por lotes.
 */
const deleteUsers = async () => {
  let usersDeletedCount = 0;
  let nextPageToken;

  console.log('Iniciando el proceso de eliminación de usuarios de Firebase Authentication...');

  try {
    do {
      // Lista los usuarios por lotes (hasta 1000 por vez).
      // nextPageToken se usa para paginar y obtener el siguiente lote.
      const listUsersResult = await admin.auth().listUsers(1000, nextPageToken);
      const uidsToDelete = listUsersResult.users.map(userRecord => userRecord.uid);

      if (uidsToDelete.length > 0) {
        console.log(`Eliminando ${uidsToDelete.length} usuarios...`);
        
        // Elimina todos los UIDs del lote actual.
        // deleteUsers devuelve un resultado con los UIDs que no se pudieron eliminar.
        const deleteResult = await admin.auth().deleteUsers(uidsToDelete);
        
        usersDeletedCount += uidsToDelete.length - deleteResult.failureCount;

        if (deleteResult.failureCount > 0) {
          console.error(`Advertencia: Falló la eliminación de ${deleteResult.failureCount} usuarios.`);
          deleteResult.errors.forEach(err => {
            console.error(`Error al eliminar UID ${err.uid}: ${err.error.message}`);
          });
        }
        console.log(`Usuarios eliminados hasta ahora: ${usersDeletedCount}`);
      }

      nextPageToken = listUsersResult.pageToken;
    } while (nextPageToken); // El bucle continúa mientras haya más páginas de usuarios.

    console.log(`✅ ¡Proceso completado! Total de usuarios eliminados: ${usersDeletedCount}`);

  } catch (error) {
    console.error('❌ Error fatal durante la eliminación de usuarios:', error);
  } finally {
    console.log('Finalizando script.');
  }
};

// ======================================================================
// PUNTO DE ENTRADA DEL SCRIPT
// Esta línea ejecuta la función deleteUsers cuando el script es llamado directamente.
// ======================================================================
if (require.main === module) {
  deleteUsers();
}
