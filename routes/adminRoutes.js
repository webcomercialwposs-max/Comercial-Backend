// routes/adminRoutes.js
const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController.js');
// Importa la función de autenticación directamente, ya que se exporta como default
const { authenticateFirebaseToken, authorizeRoles } = require('../middlewares/authMiddlewares.js');

// Middleware para todas las rutas de administrador:
// 1. authenticateFirebaseToken: Verifica que el usuario esté logueado y tenga un token válido de Firebase.
// 2. authorizeRoles(['Administrador']): Verifica que el usuario tenga el rol 'Administrador'.
router.use(authenticateFirebaseToken); // Usamos el nombre correcto de la función importada
router.use(authorizeRoles(['Administrador']));

// Ruta para obtener todas las peticiones de rol pendientes
// GET /api/admin/role-requests/pending
router.get('/role-requests/pending', adminController.getPendingRoleRequests);

// Ruta para aprobar una petición de rol
// PUT /api/admin/role-requests/:request_id/approve
router.put('/role-requests/:request_id/approve', adminController.approveRoleRequest);

// Ruta para rechazar una petición de rol
// PUT /api/admin/role-requests/:request_id/reject
router.put('/role-requests/:request_id/reject', adminController.rejectRoleRequest);

// ✅ RUTAS CORREGIDAS - usando los nombres correctos de las funciones del controlador
router.get('/users', adminController.fetchAllUsers);           // Cambio: getAllUsers → fetchAllUsers
router.get('/roles', adminController.fetchRoles);             // Cambio: getAllRoles → fetchRoles
router.put('/users/:userId/role', adminController.updateUserRole); // Cambio: :user_id → :userId y PATCH → PUT

// Ruta adicional para eliminar usuarios (si la necesitas)
router.delete('/users/:userId', adminController.deleteUser);

module.exports = router;