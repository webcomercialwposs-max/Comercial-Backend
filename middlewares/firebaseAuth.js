const firebaseAdmin = require('firebase-admin');
const responseHelper = require('../utils/responseHelper.js');

const firebaseAuthMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return responseHelper.unauthorized(res, 'Authorization header missing or invalid.');
  }

  const idToken = authHeader.split(' ')[1];

  try {
    const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken);
    req.user = decodedToken; // Agrega los datos del token decodificado al objeto de la solicitud
    next();
  } catch (error) {
    if (error.code === 'auth/id-token-expired') {
      return responseHelper.unauthorized(res, 'Firebase ID token expired.');
    }
    if (error.code === 'auth/argument-error') {
      return responseHelper.unauthorized(res, 'Invalid Firebase ID token.');
    }
    console.error('Firebase Auth Middleware Error:', error);
    return responseHelper.forbidden(res, 'Authentication failed. Access denied.');
  }
};

module.exports = firebaseAuthMiddleware;
