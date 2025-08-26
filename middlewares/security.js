const fs = require('fs');
const path = require('path');

/**
 * Configuración del logger de seguridad
 */
const LOG_CONFIG = {
    logDir: path.join(__dirname, '../logs'),
    logFile: 'security.log',
    maxLogSize: 10 * 1024 * 1024, // 10MB
    maxLogFiles: 5,
    levels: {
        ERROR: 'ERROR',
        WARN: 'WARN',
        INFO: 'INFO',
        DEBUG: 'DEBUG'
    }
};

/**
 * Crear directorio de logs si no existe
 */
const ensureLogDirectory = () => {
    if (!fs.existsSync(LOG_CONFIG.logDir)) {
        fs.mkdirSync(LOG_CONFIG.logDir, { recursive: true });
    }
};

/**
 * Rotar logs si exceden el tamaño máximo
 */
const rotateLogIfNeeded = () => {
    const logPath = path.join(LOG_CONFIG.logDir, LOG_CONFIG.logFile);
    
    try {
        if (fs.existsSync(logPath)) {
            const stats = fs.statSync(logPath);
            
            if (stats.size > LOG_CONFIG.maxLogSize) {
                const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                const rotatedName = `security-${timestamp}.log`;
                const rotatedPath = path.join(LOG_CONFIG.logDir, rotatedName);
                
                fs.renameSync(logPath, rotatedPath);
                
                // Limpiar logs antiguos
                cleanOldLogs();
            }
        }
    } catch (error) {
        console.error('Error rotating security log:', error.message);
    }
};

/**
 * Limpiar logs antiguos manteniendo solo los más recientes
 */
const cleanOldLogs = () => {
    try {
        const files = fs.readdirSync(LOG_CONFIG.logDir)
            .filter(file => file.startsWith('security-') && file.endsWith('.log'))
            .map(file => ({
                name: file,
                path: path.join(LOG_CONFIG.logDir, file),
                time: fs.statSync(path.join(LOG_CONFIG.logDir, file)).mtime
            }))
            .sort((a, b) => b.time - a.time);
        
        // Mantener solo los más recientes
        if (files.length > LOG_CONFIG.maxLogFiles) {
            const filesToDelete = files.slice(LOG_CONFIG.maxLogFiles);
            filesToDelete.forEach(file => {
                fs.unlinkSync(file.path);
            });
        }
    } catch (error) {
        console.error('Error cleaning old security logs:', error.message);
    }
};

/**
 * Formatear entrada de log
 */
const formatLogEntry = (level, message, metadata = {}) => {
    const timestamp = new Date().toISOString();
    
    // Sanitizar metadatos para evitar información sensible y evitar errores de serialización
    const sanitizedMetadata = sanitizeLogMetadata(metadata);
    
    const logEntry = {
        timestamp,
        level,
        message,
        ...sanitizedMetadata
    };
    
    return JSON.stringify(logEntry) + '\n';
};

/**
 * Sanitizar metadatos del log para evitar fugas de información sensible
 * Agregado manejo de errores para evitar que el logger falle.
 */
const sanitizeLogMetadata = (metadata) => {
    const sanitized = { ...metadata };
    
    // Lista de campos sensibles a sanitizar
    const sensitiveFields = [
        'password', 'token', 'authorization', 'cookie', 'session',
        'firebase_uid', 'email', 'phone', 'first_name', 'last_name', 'jwt',
        'idToken', 'error' // Añadido 'error' para sanear el objeto de error
    ];
    
    const sanitizeValue = (value, key) => {
        const lowerKey = key.toLowerCase();
        
        if (sensitiveFields.some(field => lowerKey.includes(field))) {
            // Manejar el caso del objeto de error de forma segura
            if (lowerKey.includes('error') && typeof value === 'object' && value !== null) {
                return {
                    message: value.message || 'Error Desconocido',
                    code: value.code || 'N/A'
                };
            }
            if (typeof value === 'string' && value.length > 8) {
                return value.substring(0, 4) + '***' + value.substring(value.length - 4);
            }
            return '***';
        }
        
        return value;
    };
    
    const sanitizeObject = (obj) => {
        if (obj === null || obj === undefined) return obj;
        
        if (typeof obj === 'object' && !Array.isArray(obj)) {
            const result = {};
            for (const [key, value] of Object.entries(obj)) {
                try {
                    if (typeof value === 'object' && value !== null) {
                        result[key] = sanitizeObject(value);
                    } else {
                        result[key] = sanitizeValue(value, key);
                    }
                } catch (e) {
                    // Si algo falla al sanear, usamos un valor de fallback
                    result[key] = 'ERROR_SANITIZING';
                }
            }
            return result;
        }
        
        return obj;
    };
    
    return sanitizeObject(sanitized);
};

/**
 * Escribir entrada al archivo de log
 */
const writeLogEntry = (logEntry) => {
    try {
        ensureLogDirectory();
        rotateLogIfNeeded();
        
        const logPath = path.join(LOG_CONFIG.logDir, LOG_CONFIG.logFile);
        fs.appendFileSync(logPath, logEntry);
        
    } catch (error) {
        console.error('Failed to write security log:', error.message);
        // Fallback: log to console
        console.log('SECURITY LOG:', logEntry.trim());
    }
};

/**
 * Logger de seguridad principal
 */
const securityLogger = {
    /**
     * Log de errores críticos de seguridad
     */
    error: (message, metadata = {}) => {
        const logEntry = formatLogEntry(LOG_CONFIG.levels.ERROR, message, {
            ...metadata,
            severity: 'HIGH'
        });
        
        writeLogEntry(logEntry);
        
        // También log a consola para errores críticos
        console.error(`[SECURITY ERROR] ${message}`, sanitizeLogMetadata(metadata));
    },
    
    /**
     * Log de advertencias de seguridad
     */
    warn: (message, metadata = {}) => {
        const logEntry = formatLogEntry(LOG_CONFIG.levels.WARN, message, {
            ...metadata,
            severity: 'MEDIUM'
        });
        
        writeLogEntry(logEntry);
        
        // Log a consola en desarrollo
        if (process.env.NODE_ENV === 'development') {
            console.warn(`[SECURITY WARN] ${message}`, sanitizeLogMetadata(metadata));
        }
    },
    
    /**
     * Log de información de seguridad
     */
    info: (message, metadata = {}) => {
        const logEntry = formatLogEntry(LOG_CONFIG.levels.INFO, message, {
            ...metadata,
            severity: 'LOW'
        });
        
        writeLogEntry(logEntry);
        
        // Log a consola en desarrollo
        if (process.env.NODE_ENV === 'development') {
            console.info(`[SECURITY INFO] ${message}`, sanitizeLogMetadata(metadata));
        }
    },
    
    /**
     * Log de debug (solo en desarrollo)
     */
    debug: (message, metadata = {}) => {
        if (process.env.NODE_ENV === 'development') {
            const logEntry = formatLogEntry(LOG_CONFIG.levels.DEBUG, message, metadata);
            writeLogEntry(logEntry);
            console.debug(`[SECURITY DEBUG] ${message}`, sanitizeLogMetadata(metadata));
        }
    }
};

/**
 * Middleware para logging automático de requests
 */
const logRequest = (req, res, next) => {
    // Si no estamos en producción, simplemente pasamos al siguiente middleware
    if (process.env.NODE_ENV !== 'production') {
        return next();
    }
    
    // El resto del código de logging solo se ejecuta en producción
    const startTime = Date.now();
    
    // Log del request entrante
    securityLogger.info('Incoming request', {
        method: req.method,
        url: req.originalUrl,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        userId: req.user?.userId || req.user?.user_id || 'anonymous',
        hasAuth: !!req.headers.authorization
    });
    
    // Interceptar la respuesta
    const originalSend = res.send;
    res.send = function(data) {
        const duration = Date.now() - startTime;
        
        securityLogger.info('Request completed', {
            method: req.method,
            url: req.originalUrl,
            statusCode: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip,
            userId: req.user?.userId || req.user?.user_id || 'anonymous'
        });
        
        return originalSend.call(this, data);
    };
    
    next();
};

/**
 * Middleware para detectar intentos de ataques comunes
 */
const detectSuspiciousActivity = (req, res, next) => {
    // Si no estamos en producción, simplemente pasamos al siguiente middleware
    if (process.env.NODE_ENV !== 'production') {
        return next();
    }

    const suspiciousPatterns = [
        /(<script|javascript:|data:)/i,  // XSS attempts
        /(union|select|insert|update|delete|drop|exec)/i,  // SQL injection
        /(..\/|..\\)/,  // Path traversal
        /(<\?php|<%) /i,  // Server-side injection
    ];
    
    const checkForPatterns = (data) => {
        if (typeof data === 'string') {
            return suspiciousPatterns.some(pattern => pattern.test(data));
        }
        if (typeof data === 'object' && data !== null) {
            return Object.values(data).some(value => checkForPatterns(value));
        }
        return false;
    };
    
    // Verificar parámetros de URL, cuerpo y parámetros de ruta
    const suspicious = checkForPatterns(req.originalUrl) ||
                      checkForPatterns(req.body) ||
                      checkForPatterns(req.query) ||
                      checkForPatterns(req.params);
    
    if (suspicious) {
        securityLogger.warn('Suspicious activity detected', {
            ip: req.ip,
            url: req.originalUrl,
            method: req.method,
            userAgent: req.get('User-Agent'),
            userId: req.user?.userId || 'anonymous',
            body: req.body,
            query: req.query,
            params: req.params
        });
        
        return res.status(400).json({
            message: 'Solicitud inválida detectada.'
        });
    }
    
    next();
};

/**
 * Middleware de rate limiting básico - REMOVIDO PARA DESARROLLO
 * Descomenta y configura cuando necesites rate limiting en producción
 */
/*
const createRateLimiter = (maxRequests = 500, windowMs = 15 * 60 * 1000) => {
    const requests = new Map();
    
    return (req, res, next) => {
        const key = req.ip;
        const now = Date.now();
        const windowStart = now - windowMs;
        
        // Limpiar requests antiguos
        if (requests.has(key)) {
            const userRequests = requests.get(key).filter(time => time > windowStart);
            requests.set(key, userRequests);
        } else {
            requests.set(key, []);
        }
        
        const currentRequests = requests.get(key);
        
        if (currentRequests.length >= maxRequests) {
            securityLogger.warn('Rate limit exceeded', {
                ip: req.ip,
                requestCount: currentRequests.length,
                maxRequests,
                windowMs,
                userAgent: req.get('User-Agent')
            });
            
            return res.status(429).json({
                message: 'Demasiadas solicitudes. Intenta de nuevo más tarde.'
            });
        }
        
        currentRequests.push(now);
        next();
    };
};
*/

// Función dummy para evitar errores si se importa
const createRateLimiter = () => {
    console.log('🟡 Rate limiter is DISABLED for development');
    return (req, res, next) => next();
};

module.exports = {
    securityLogger,
    logRequest,
    detectSuspiciousActivity,
    createRateLimiter
};
