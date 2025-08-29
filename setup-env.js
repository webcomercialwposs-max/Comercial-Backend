#!/usr/bin/env node

/**
 * Script para configurar el archivo .env con las credenciales de Supabase
 * Ejecuta: node setup-env.js
 */

const fs = require('fs');
const path = require('path');

console.log('🚀 Configurando archivo .env para Supabase');
console.log('==========================================\n');

// Verificar si ya existe el archivo .env
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
    console.log('⚠️  El archivo .env ya existe.');
    const readline = require('readline');
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    rl.question('¿Deseas sobrescribirlo? (y/N): ', (answer) => {
        if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
            createEnvFile();
        } else {
            console.log('❌ Operación cancelada. El archivo .env no se modificó.');
        }
        rl.close();
    });
} else {
    createEnvFile();
}

function createEnvFile() {
    const envContent = `# Configuración de Supabase/PostgreSQL
# Obtén estas credenciales desde tu proyecto de Supabase:
# Settings > Database > Connection string

DB_USER=tu_usuario_supabase
DB_HOST=db.tu_proyecto.supabase.co
DB_DATABASE=postgres
DB_PASSWORD=tu_password_supabase
DB_PORT=5432

# Puerto del servidor
PORT=3000

# Configuración de CORS
CORS_ORIGIN=https://comercial-wposs-ft.vercel.app

# Configuración del entorno
NODE_ENV=development

# Configuración de Firebase (opcional)
# FIREBASE_PROJECT_ID=tu_proyecto_id
`;

    try {
        fs.writeFileSync(envPath, envContent);
        console.log('✅ Archivo .env creado exitosamente!');
        console.log('\n📝 Ahora necesitas:');
        console.log('   1. Ir a tu proyecto en supabase.com');
        console.log('   2. Settings > Database');
        console.log('   3. Copiar las credenciales de Connection string');
        console.log('   4. Reemplazar los valores en el archivo .env');
        console.log('\n🔗 Ejemplo de Connection string de Supabase:');
        console.log('   postgresql://postgres:[YOUR-PASSWORD]@db.[YOUR-PROJECT-REF].supabase.co:5432/postgres');
        console.log('\n💡 Después ejecuta: npm start');
    } catch (error) {
        console.error('❌ Error al crear el archivo .env:', error.message);
    }
}

