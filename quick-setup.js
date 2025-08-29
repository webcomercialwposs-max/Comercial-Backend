#!/usr/bin/env node

/**
 * Script de configuración rápida para producción
 * Ejecuta: node quick-setup.js
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('🚀 Configuración rápida para producción');
console.log('=======================================\n');

const runCommand = (command, description) => {
    try {
        console.log(`🔄 ${description}...`);
        execSync(command, { stdio: 'inherit' });
        console.log(`✅ ${description} completado`);
        return true;
    } catch (error) {
        console.error(`❌ Error en ${description}:`, error.message);
        return false;
    }
};

const createProductionEnv = () => {
    console.log('📝 Creando archivo .env para producción...');
    
    const envContent = `# Configuración de producción - Supabase
# IMPORTANTE: Reemplaza estos valores con tus credenciales reales

DB_USER=postgres
DB_HOST=db.tu_proyecto.supabase.co
DB_DATABASE=postgres
DB_PASSWORD=tu_password_supabase
DB_PORT=5432

# Puerto del servidor
PORT=3000

# Configuración de CORS para producción
CORS_ORIGIN=https://comercial-wposs-ft.vercel.app

# Entorno de producción
NODE_ENV=production

# Configuración de seguridad
# JWT_SECRET=tu_jwt_secret_super_seguro
# SESSION_SECRET=tu_session_secret_super_seguro
`;

    try {
        fs.writeFileSync('.env', envContent);
        console.log('✅ Archivo .env creado');
        console.log('⚠️  IMPORTANTE: Edita el archivo .env con tus credenciales reales de Supabase');
        return true;
    } catch (error) {
        console.error('❌ Error al crear .env:', error.message);
        return false;
    }
};

const main = async () => {
    console.log('🔍 Verificando requisitos...');
    
    // Verificar Node.js
    const nodeVersion = process.version;
    console.log(`✅ Node.js: ${nodeVersion}`);
    
    // Verificar npm
    try {
        const npmVersion = execSync('npm --version', { encoding: 'utf8' }).trim();
        console.log(`✅ npm: ${npmVersion}`);
    } catch (error) {
        console.error('❌ npm no está disponible');
        return false;
    }
    
    console.log('\n📦 Instalando dependencias...');
    if (!runCommand('npm install', 'Instalación de dependencias')) {
        return false;
    }
    
    console.log('\n📝 Configurando variables de entorno...');
    if (!createProductionEnv()) {
        return false;
    }
    
    console.log('\n🗄️  Configurando base de datos...');
    if (!runCommand('npm run setup-db', 'Configuración de tablas en Supabase')) {
        console.log('⚠️  La configuración de la base de datos falló');
        console.log('   Esto puede ser normal si las credenciales no están configuradas aún');
    }
    
    console.log('\n🔍 Ejecutando diagnóstico...');
    if (!runCommand('npm run diagnose', 'Diagnóstico del sistema')) {
        console.log('⚠️  El diagnóstico encontró problemas');
    }
    
    console.log('\n🎉 CONFIGURACIÓN COMPLETADA');
    console.log('============================');
    console.log('\n📋 Próximos pasos:');
    console.log('   1. Edita el archivo .env con tus credenciales de Supabase');
    console.log('   2. Ejecuta: npm run check');
    console.log('   3. Si todo está bien, ejecuta: npm start');
    console.log('   4. Verifica: http://localhost:3000/api/status');
    
    console.log('\n🔗 URLs importantes:');
    console.log('   - Estado de la API: http://localhost:3000/api/status');
    console.log('   - Documentación: README.md');
    
    console.log('\n⚠️  RECORDATORIOS:');
    console.log('   - Nunca subas el archivo .env a Git');
    console.log('   - Mantén tus credenciales seguras');
    console.log('   - Verifica que tu proyecto de Supabase esté activo');
    
    return true;
};

// Ejecutar si se llama directamente
if (require.main === module) {
    main().then(success => {
        if (!success) {
            console.log('\n❌ La configuración no se completó correctamente');
            process.exit(1);
        }
    });
}

module.exports = { main };
