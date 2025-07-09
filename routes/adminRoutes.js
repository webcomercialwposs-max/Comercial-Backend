// routes/adminRoutes.js
const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController.js');
const { authenticateToken, authorizeRoles } = require('../middlewares/authMiddlewares.js');

// Middleware para todas las rutas de administrador:
// 1. authenticateToken: Verifica que el usuario esté logueado y tenga un token válido.
// 2. authorizeRoles(['Administrador']): Verifica que el usuario tenga el rol 'Administrador'.
router.use(authenticateToken);
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

module.exports = router;