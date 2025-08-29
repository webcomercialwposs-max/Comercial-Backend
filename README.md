# 🚀 Backend Comercial - Firebase + Supabase

Backend robusto para sistema comercial que integra Firebase Authentication con Supabase (PostgreSQL) para el almacenamiento de datos.

## ✨ Características

- 🔥 **Firebase Authentication** - Autenticación segura de usuarios
- 🗄️ **Supabase (PostgreSQL)** - Base de datos robusta y escalable
- 🛡️ **Seguridad avanzada** - Validaciones, sanitización y logging de seguridad
- 📱 **API RESTful** - Endpoints bien estructurados para autenticación y gestión de usuarios
- 🔄 **Transacciones** - Manejo seguro de operaciones de base de datos
- 📊 **Logging** - Sistema de logs para monitoreo y debugging

## 🚀 Instalación

### 1. Clonar el repositorio
```bash
git clone <tu-repositorio>
cd Comercial-Backend
```

### 2. Instalar dependencias
```bash
npm install
```

### 3. Configurar variables de entorno
```bash
npm run setup
```

O crea manualmente un archivo `.env` con:

```env
# Configuración de Supabase
DB_USER=tu_usuario_supabase
DB_HOST=db.tu_proyecto.supabase.co
DB_DATABASE=postgres
DB_PASSWORD=tu_password_supabase
DB_PORT=5432

# Puerto del servidor
PORT=3000

# CORS
CORS_ORIGIN=https://comercial-wposs-ft.vercel.app

# Entorno
NODE_ENV=development
```

### 4. Obtener credenciales de Supabase

1. Ve a [supabase.com](https://supabase.com)
2. Selecciona tu proyecto
3. Ve a **Settings** → **Database**
4. Copia las credenciales de **Connection string**
5. Actualiza tu archivo `.env`

### 5. Verificar Firebase

Asegúrate de que `serviceAccountKey.json` esté presente en la raíz del proyecto.

## 🏃‍♂️ Uso

### Iniciar servidor
```bash
npm start
```

### Modo desarrollo (con auto-reload)
```bash
npm run dev
```

### Probar conexión a base de datos
```bash
npm run test-db
```

### Verificar estado de la API
```bash
npm run status
```

## 📡 Endpoints de la API

### Autenticación
- `POST /api/auth/login` - Login/Registro con Firebase
- `GET /api/auth/profile` - Obtener perfil del usuario
- `PUT /api/auth/profile` - Actualizar perfil del usuario

### Estado del sistema
- `GET /` - Estado básico de la API
- `GET /api/status` - Estado detallado de todos los servicios

## 🗄️ Estructura de la Base de Datos

### Tablas principales:
- `users` - Información básica de usuarios
- `user_profiles` - Perfiles extendidos de usuarios
- `roles` - Roles y permisos del sistema

## 🔧 Scripts disponibles

- `npm start` - Iniciar servidor en producción
- `npm run dev` - Iniciar servidor en modo desarrollo
- `npm run setup` - Configurar archivo .env
- `npm run test-db` - Probar conexión a Supabase
- `npm run status` - Verificar estado de la API

## 🚨 Solución de Problemas

### Error: "Faltan variables de entorno"
- Verifica que el archivo `.env` existe
- Ejecuta `npm run setup` para crear la plantilla
- Completa las credenciales de Supabase

### Error: "No se pudo conectar a Supabase"
- Verifica tu conexión a internet
- Confirma que las credenciales en `.env` son correctas
- Asegúrate de que tu proyecto de Supabase esté activo

### Error: "Firebase Admin SDK no está inicializado"
- Verifica que `serviceAccountKey.json` existe
- Confirma que el archivo tiene las credenciales correctas

## 📝 Logs y Monitoreo

El sistema incluye logging detallado para:
- Conexiones a base de datos
- Autenticaciones exitosas y fallidas
- Errores de seguridad
- Rendimiento de operaciones

## 🔒 Seguridad

- Validación y sanitización de datos de entrada
- Consultas preparadas para prevenir SQL injection
- Logging de eventos de seguridad
- Manejo seguro de tokens de Firebase
- Transacciones para operaciones críticas

## 📊 Monitoreo

- Endpoint `/api/status` para verificar estado de servicios
- Logs detallados en consola
- Métricas de rendimiento
- Manejo graceful de cierre del servidor

## 🤝 Contribución

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia ISC.

## 🆘 Soporte

Si tienes problemas:
1. Revisa los logs del servidor
2. Verifica la configuración en `.env`
3. Ejecuta `npm run test-db` para probar la conexión
4. Revisa el endpoint `/api/status` para diagnóstico

---

**¡Happy Coding! 🎉**

