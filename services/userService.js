const { pool } = require('../db/db.js');
const DEFAULT_USER_ROLE_ID = 1; // Asume que el ID del rol 'Usuario' es 1

const findOrCreateUser = async (client, firebase_uid, email) => {
  // Consulta para encontrar un usuario por su firebase_uid
  const result = await client.query(
    'SELECT user_id, email, role_name FROM users JOIN roles ON users.role_id = roles.role_id WHERE firebase_uid = $1',
    [firebase_uid]
  );

  if (result.rows.length > 0) {
    return result.rows[0];
  }

  // Si no se encuentra, crea un nuevo usuario
  const newUserResult = await client.query(
    'INSERT INTO users (firebase_uid, email, role_id) VALUES ($1, $2, $3) RETURNING user_id, email',
    [firebase_uid, email, DEFAULT_USER_ROLE_ID]
  );

  // También crea un perfil vacío para el nuevo usuario
  await client.query(
    'INSERT INTO user_profiles (user_id) VALUES ($1)',
    [newUserResult.rows[0].user_id]
  );

  return { ...newUserResult.rows[0], role_name: 'Usuario' }; // Asigna el rol por defecto
};

const getUserProfile = async (client, user_id) => {
  const result = await client.query(
    'SELECT first_name, last_name, phone, city, profile_picture_url FROM user_profiles WHERE user_id = $1',
    [user_id]
  );
  return result.rows[0] || null;
};

const getUserProfileByFirebaseUID = async (client, firebase_uid) => {
  const result = await client.query(
    `SELECT
       p.first_name,
       p.last_name,
       p.phone,
       p.city,
       p.profile_picture_url,
       u.email,
       u.firebase_uid,
       r.role_name
     FROM users u
     JOIN user_profiles p ON u.user_id = p.user_id
     JOIN roles r ON u.role_id = r.role_id
     WHERE u.firebase_uid = $1`,
    [firebase_uid]
  );
  return result.rows[0] || null;
};

const updateUserProfile = async (client, firebase_uid, profileData) => {
  const { first_name, last_name, phone, city, profile_picture_url } = profileData;

  // Usa una subconsulta para encontrar el user_id a partir del firebase_uid
  const result = await client.query(
    `UPDATE user_profiles
     SET
       first_name = COALESCE($1, first_name),
       last_name = COALESCE($2, last_name),
       phone = COALESCE($3, phone),
       city = COALESCE($4, city),
       profile_picture_url = COALESCE($5, profile_picture_url)
     WHERE user_id = (SELECT user_id FROM users WHERE firebase_uid = $6)
     RETURNING *`,
    [first_name, last_name, phone, city, profile_picture_url, firebase_uid]
  );
  return result.rows[0] || null;
};

module.exports = {
  findOrCreateUser,
  getUserProfile,
  getUserProfileByFirebaseUID,
  updateUserProfile,
};
