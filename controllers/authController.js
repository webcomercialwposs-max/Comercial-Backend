const firebaseAdmin = require('firebase-admin');
const { pool } = require('../db/db.js');
const responseHelper = require('../utils/responseHelper.js');
const userService = require('../services/userService.js');

// POST /api/auth/login
// Lógica de autenticación: verifica el token de Firebase y sincroniza el usuario con la DB.
const firebaseLogin = async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    return responseHelper.badRequest(res, 'ID Token is required.');
  }

  try {
    const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken);
    const { uid, email } = decodedToken;

    // Inicia una transacción para asegurar la consistencia de los datos
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const user = await userService.findOrCreateUser(client, uid, email);

      // Si el usuario ya existe, lo retorna. Si no, lo crea y le asigna un rol por defecto.
      const userProfile = await userService.getUserProfile(client, user.user_id);

      await client.query('COMMIT');

      const authResponse = {
        message: 'Authentication successful.',
        user: {
          firebase_uid: uid,
          email: user.email,
          role: user.role_name,
        },
        profile: userProfile,
      };

      responseHelper.success(res, 200, authResponse);
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Transaction Error:', error);
      responseHelper.serverError(res, 'Failed to process authentication transaction.');
    } finally {
      client.release();
    }
  } catch (error) {
    if (error.code === 'auth/id-token-expired' || error.code === 'auth/argument-error') {
      return responseHelper.unauthorized(res, 'Invalid or expired Firebase ID token.');
    }
    console.error('Firebase Auth Error:', error);
    responseHelper.serverError(res, 'An error occurred during Firebase authentication.');
  }
};

// GET /api/auth/profile
// Obtiene el perfil completo del usuario autenticado.
const getUserProfile = async (req, res) => {
  const firebase_uid = req.user.uid; // Asume que el middleware de auth coloca el UID aquí

  try {
    const client = await pool.connect();
    try {
      const userProfile = await userService.getUserProfileByFirebaseUID(client, firebase_uid);
      if (!userProfile) {
        return responseHelper.notFound(res, 'User profile not found.');
      }
      responseHelper.success(res, 200, userProfile);
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Error fetching user profile:', error);
    responseHelper.serverError(res, 'An error occurred while fetching the profile.');
  }
};

// PUT /api/auth/profile
// Actualiza los campos del perfil del usuario.
const updateUserProfile = async (req, res) => {
  const firebase_uid = req.user.uid;
  const { first_name, last_name, phone, city, profile_picture_url } = req.body;

  try {
    const client = await pool.connect();
    try {
      const updatedProfile = await userService.updateUserProfile(client, firebase_uid, {
        first_name,
        last_name,
        phone,
        city,
        profile_picture_url,
      });

      if (!updatedProfile) {
        return responseHelper.notFound(res, 'User profile not found for update.');
      }

      responseHelper.success(res, 200, updatedProfile);
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Error updating user profile:', error);
    responseHelper.serverError(res, 'An error occurred while updating the profile.');
  }
};

// GET /api/auth/status
// Verifica si el token es válido y si el usuario existe en la DB
const getAuthStatus = (req, res) => {
  // Si el middleware de auth ya se ejecutó sin errores, el token es válido.
  const { uid, email } = req.user;
  responseHelper.success(res, 200, {
    message: 'Session is active.',
    user: { uid, email },
  });
};

module.exports = {
  firebaseLogin,
  getUserProfile,
  updateUserProfile,
  getAuthStatus,
};
