# 🚀 Backend Comercial - Firebase + Supabase

Backend robusto para sistema comercial que integra Firebase Authentication con Supabase (PostgreSQL) para el almacenamiento de datos.

## ✨ Características

- 🔥 **Firebase Authentication** - Autenticación segura de usuarios
- 🗄️ **Supabase (PostgreSQL)** - Base de datos robusta y escalable
- 🛡️ **Seguridad avanzada** - Validaciones, sanitización y logging de seguridad
- 📱 **API RESTful** - Endpoints bien estructurados para autenticación y gestión de usuarios
- 🔄 **Transacciones** - Manejo seguro de operaciones de base de datos
- 📊 **Logging** - Sistema de logs para monitoreo y debugging
- 🔧 **Scripts de configuración** - Herramientas para setup rápido y diagnóstico

## 🚀 Instalación Rápida

### Opción 1: Configuración automática
```bash
# Clonar y configurar automáticamente
git clone <tu-repositorio>
cd Comercial-Backend
node quick-setup.js
```

### Opción 2: Configuración manual
```bash
# 1. Clonar el repositorio
git clone <tu-repositorio>
cd Comercial-Backend

# 2. Instalar dependencias
npm install

# 3. Configurar variables de entorno
npm run setup

# 4. Configurar base de datos
npm run setup-db

# 5. Verificar configuración
npm run check

# 6. Iniciar servidor
npm start
```

## 📋 Configuración de Variables de Entorno

Crea un archivo `.env` con las siguientes variables:

```env
# Configuración de Supabase
DB_USER=postgres
DB_HOST=db.tu_proyecto.supabase.co
DB_DATABASE=postgres
DB_PASSWORD=tu_password_supabase
DB_PORT=5432

# Puerto del servidor
PORT=3000

# CORS
CORS_ORIGIN=https://comercial-wposs-ft.vercel.app

# Entorno
NODE_ENV=production
```

### 🔑 Obtener credenciales de Supabase

1. Ve a [supabase.com](https://supabase.com)
2. Selecciona tu proyecto
3. Ve a **Settings** → **Database**
4. Copia las credenciales de **Connection string**
5. Extrae los valores para tu archivo `.env`

## 🏃‍♂️ Uso

### Scripts disponibles

| Comando | Descripción |
|---------|-------------|
| `npm start` | Iniciar servidor en producción |
| `npm run dev` | Iniciar servidor en modo desarrollo |
| `npm run setup` | Configurar archivo .env |
| `npm run setup-db` | Crear tablas en Supabase |
| `npm run diagnose` | Diagnóstico completo del sistema |
| `npm run test-db` | Probar conexión a Supabase |
| `npm run status` | Verificar estado de la API |
| `npm run check` | Diagnóstico + prueba de conexión |
| `npm run deploy` | Configurar BD + iniciar servidor |
| `node quick-setup.js` | Configuración automática completa |

### Iniciar servidor
```bash
npm start
```

### Modo desarrollo (con auto-reload)
```bash
npm run dev
```

### Verificar estado completo
```bash
npm run check
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
- `roles` - Roles y permisos del sistema
- `users` - Información básica de usuarios
- `user_profiles` - Perfiles extendidos de usuarios

### Índices optimizados:
- `idx_users_firebase_uid` - Búsqueda por Firebase UID
- `idx_users_email` - Búsqueda por email
- `idx_users_role_id` - Filtrado por rol

## 🔧 Scripts de Utilidad

### Diagnóstico completo
```bash
npm run diagnose
```
Verifica:
- Variables de entorno
- Dependencias instaladas
- Estructura de archivos
- Configuración de Firebase

### Configuración de base de datos
```bash
npm run setup-db
```
Crea:
- Tabla de roles
- Tabla de usuarios
- Tabla de perfiles
- Índices optimizados
- Triggers de actualización

### Verificación de conexión
```bash
npm run test-db
```
Prueba la conexión a Supabase y muestra información del servidor.

## 🚨 Solución de Problemas

### Error: "502 Bad Gateway"
- **Causa**: Servidor no puede iniciarse por falta de configuración
- **Solución**: 
  1. Ejecuta `npm run diagnose`
  2. Configura el archivo `.env` con credenciales de Supabase
  3. Ejecuta `npm run setup-db`

### Error: "Faltan variables de entorno"
- **Causa**: Archivo `.env` no existe o está mal configurado
- **Solución**: 
  1. Ejecuta `npm run setup`
  2. Completa las credenciales de Supabase

### Error: "No se pudo conectar a Supabase"
- **Causa**: Credenciales incorrectas o proyecto inactivo
- **Solución**:
  1. Verifica tu conexión a internet
  2. Confirma las credenciales en `.env`
  3. Asegúrate de que tu proyecto de Supabase esté activo

### Error: "Firebase Admin SDK no está inicializado"
- **Causa**: Falta `serviceAccountKey.json`
- **Solución**:
  1. Verifica que `serviceAccountKey.json` existe
  2. Confirma que tiene las credenciales correctas

## 📝 Logs y Monitoreo

### Logs del sistema
- Conexiones a base de datos
- Autenticaciones exitosas y fallidas
- Errores de seguridad
- Rendimiento de operaciones

### Endpoint de monitoreo
```bash
curl http://localhost:3000/api/status
```

Respuesta:
```json
{
  "status": "online",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "services": {
    "firebase": "✅ Funcionando",
    "supabase": "✅ Conectado",
    "database": "✅ PostgreSQL (Supabase)"
  },
  "environment": {
    "node_version": "v18.0.0",
    "platform": "linux",
    "port": 3000
  }
}
```

## 🔒 Seguridad

### Características implementadas:
- ✅ Validación y sanitización de datos de entrada
- ✅ Consultas preparadas para prevenir SQL injection
- ✅ Logging de eventos de seguridad
- ✅ Manejo seguro de tokens de Firebase
- ✅ Transacciones para operaciones críticas
- ✅ Timeouts en verificaciones de tokens
- ✅ Manejo de race conditions

### Configuración SSL para Supabase:
```javascript
ssl: {
    rejectUnauthorized: false // Necesario para Supabase
}
```

## 📊 Monitoreo y Métricas

### Endpoints de monitoreo:
- `GET /api/status` - Estado de todos los servicios
- `GET /` - Estado básico de la API

### Logs estructurados:
- Timestamps precisos
- Información de contexto
- Métricas de rendimiento
- Trazabilidad de errores

### Manejo graceful:
- Cierre ordenado del servidor
- Liberación de conexiones de BD
- Manejo de señales SIGTERM/SIGINT

## 🚀 Despliegue

### Configuración para producción:
```bash
# 1. Configuración automática
node quick-setup.js

# 2. Editar .env con credenciales reales
# 3. Verificar configuración
npm run check

# 4. Iniciar servidor
npm start
```

### Variables de entorno para producción:
```env
NODE_ENV=production
PORT=3000
CORS_ORIGIN=https://tu-dominio.com
```

## 🤝 Contribución

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📄 Licencia

Este proyecto está bajo la Licencia ISC.

## 🆘 Soporte

### Diagnóstico automático:
```bash
npm run diagnose
```

### Verificación completa:
```bash
npm run check
```

### Si tienes problemas:
1. Ejecuta `npm run diagnose` para identificar problemas
2. Verifica la configuración en `.env`
3. Ejecuta `npm run test-db` para probar la conexión
4. Revisa el endpoint `/api/status` para diagnóstico
5. Consulta los logs del servidor

### Contacto:
- Revisa los logs detallados en consola
- Verifica el estado de Supabase en tu dashboard
- Confirma que Firebase esté configurado correctamente

---

**¡Happy Coding! 🎉**

