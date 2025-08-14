// routes/adminRoutes.js
const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController.js');
// Importa la función de autenticación y autorización
const { isAuthenticated, authorizeRoles } = require('../middlewares/authMiddlewares.js');

// Middleware para todas las rutas de administrador:
// 1. isAuthenticated: Verifica que el usuario esté logueado y tenga un token válido de Firebase.
// 2. authorizeRoles(['Administrador']): Verifica que el usuario tenga el rol 'Administrador'.
router.use(isAuthenticated); 
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

// Rutas de gestión de usuarios y roles
router.get('/users', adminController.fetchAllUsers);
router.get('/roles', adminController.fetchRoles);
router.put('/users/:userId/role', adminController.updateUserRole);

// Ruta adicional para eliminar usuarios (si la necesitas)
router.delete('/users/:userId', adminController.deleteUser);

// NUEVA RUTA: Para bloquear/desbloquear usuarios
// PUT /api/admin/users/:firebaseUid/block
// Esta ruta usa el firebaseUid, tal como lo llama tu frontend.
router.put('/users/:firebaseUid/block', adminController.toggleUserBlockStatus);

module.exports = router;