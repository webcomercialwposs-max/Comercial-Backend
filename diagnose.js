#!/usr/bin/env node

/**
 * Script de diagnóstico completo para el backend
 * Ejecuta: node diagnose.js
 */

const fs = require('fs');
const path = require('path');

console.log('🔍 Diagnóstico completo del Backend Comercial');
console.log('=============================================\n');

// Función para verificar archivos
const checkFile = (filePath, description) => {
    const exists = fs.existsSync(filePath);
    console.log(`${exists ? '✅' : '❌'} ${description}: ${exists ? 'Presente' : 'FALTANTE'}`);
    return exists;
};

// Función para verificar variables de entorno
const checkEnvVars = () => {
    console.log('\n📋 Verificando variables de entorno:');
    
    try {
        require('dotenv').config();
        
        const requiredVars = ['DB_USER', 'DB_HOST', 'DB_DATABASE', 'DB_PASSWORD', 'DB_PORT'];
        const missingVars = [];
        
        requiredVars.forEach(varName => {
            const value = process.env[varName];
            if (value && value !== 'tu_usuario_supabase' && value !== 'tu_password_supabase') {
                console.log(`✅ ${varName}: Configurado`);
            } else {
                console.log(`❌ ${varName}: ${value || 'No configurado'}`);
                missingVars.push(varName);
            }
        });
        
        if (missingVars.length > 0) {
            console.log('\n⚠️  Variables faltantes o con valores por defecto:');
            missingVars.forEach(varName => {
                console.log(`   - ${varName}`);
            });
            return false;
        }
        
        return true;
    } catch (error) {
        console.log('❌ Error al cargar variables de entorno:', error.message);
        return false;
    }
};

// Función para verificar dependencias
const checkDependencies = () => {
    console.log('\n📦 Verificando dependencias:');
    
    try {
        const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
        const requiredDeps = ['express', 'pg', 'firebase-admin', 'dotenv'];
        
        requiredDeps.forEach(dep => {
            if (packageJson.dependencies[dep]) {
                console.log(`✅ ${dep}: ${packageJson.dependencies[dep]}`);
            } else {
                console.log(`❌ ${dep}: No instalado`);
            }
        });
        
        return true;
    } catch (error) {
        console.log('❌ Error al verificar dependencias:', error.message);
        return false;
    }
};

// Función para verificar estructura de archivos
const checkFileStructure = () => {
    console.log('\n📁 Verificando estructura de archivos:');
    
    const requiredFiles = [
        { path: 'index.js', desc: 'Archivo principal del servidor' },
        { path: 'db/db.js', desc: 'Configuración de base de datos' },
        { path: 'controllers/authController.js', desc: 'Controlador de autenticación' },
        { path: 'routes/authRoutes.js', desc: 'Rutas de autenticación' },
        { path: 'middlewares/validations.js', desc: 'Validaciones' },
        { path: 'serviceAccountKey.json', desc: 'Credenciales de Firebase' },
        { path: 'package.json', desc: 'Configuración del proyecto' }
    ];
    
    let allFilesExist = true;
    requiredFiles.forEach(file => {
        if (!checkFile(file.path, file.desc)) {
            allFilesExist = false;
        }
    });
    
    return allFilesExist;
};

// Función para generar reporte
const generateReport = (envOk, depsOk, filesOk) => {
    console.log('\n📊 REPORTE DE DIAGNÓSTICO');
    console.log('==========================');
    
    const issues = [];
    
    if (!envOk) {
        issues.push('❌ Variables de entorno no configuradas correctamente');
    }
    
    if (!depsOk) {
        issues.push('❌ Dependencias faltantes');
    }
    
    if (!filesOk) {
        issues.push('❌ Archivos del proyecto faltantes');
    }
    
    if (issues.length === 0) {
        console.log('🎉 Todo está configurado correctamente!');
        console.log('\n💡 Próximos pasos:');
        console.log('   1. Ejecuta: npm run setup-db');
        console.log('   2. Ejecuta: npm start');
        console.log('   3. Verifica: http://localhost:3000/api/status');
    } else {
        console.log('⚠️  Problemas encontrados:');
        issues.forEach(issue => console.log(`   ${issue}`));
        
        console.log('\n🔧 Soluciones:');
        if (!envOk) {
            console.log('   1. Ejecuta: npm run setup');
            console.log('   2. Completa las credenciales de Supabase en .env');
        }
        if (!depsOk) {
            console.log('   1. Ejecuta: npm install');
        }
        if (!filesOk) {
            console.log('   1. Verifica que todos los archivos estén presentes');
            console.log('   2. Clona nuevamente el repositorio si es necesario');
        }
    }
    
    return issues.length === 0;
};

// Función principal
const runDiagnosis = async () => {
    const envOk = checkEnvVars();
    const depsOk = checkDependencies();
    const filesOk = checkFileStructure();
    
    const allOk = generateReport(envOk, depsOk, filesOk);
    
    if (allOk) {
        console.log('\n🚀 El backend está listo para funcionar!');
    } else {
        console.log('\n⚠️  Resuelve los problemas antes de continuar.');
    }
    
    return allOk;
};

// Ejecutar diagnóstico
if (require.main === module) {
    runDiagnosis();
}

module.exports = { runDiagnosis };
