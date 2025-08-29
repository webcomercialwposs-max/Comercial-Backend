#!/usr/bin/env node

/**
 * Script para crear las tablas necesarias en Supabase
 * Ejecuta: node setup-database.js
 */

const { pool } = require('./db/db.js');

const createTables = async () => {
    let client;
    try {
        client = await pool.connect();
        
        console.log('🔄 Creando tablas en Supabase...');
        
        // Crear tabla de roles
        await client.query(`
            CREATE TABLE IF NOT EXISTS roles (
                role_id SERIAL PRIMARY KEY,
                role_name VARCHAR(50) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ Tabla roles creada/verificada');
        
        // Insertar rol por defecto si no existe
        await client.query(`
            INSERT INTO roles (role_name) 
            VALUES ('Usuario') 
            ON CONFLICT (role_name) DO NOTHING;
        `);
        console.log('✅ Rol por defecto insertado');
        
        // Crear tabla de usuarios
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                firebase_uid VARCHAR(128) UNIQUE,
                email VARCHAR(255) UNIQUE NOT NULL,
                role_id INTEGER REFERENCES roles(role_id) DEFAULT 1,
                is_blocked BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ Tabla users creada/verificada');
        
        // Crear tabla de perfiles de usuario
        await client.query(`
            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id INTEGER PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                first_name VARCHAR(100),
                last_name VARCHAR(100),
                phone VARCHAR(20),
                city VARCHAR(100),
                profile_picture_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ Tabla user_profiles creada/verificada');
        
        // Crear índices para mejor rendimiento
        await client.query(`
            CREATE INDEX IF NOT EXISTS idx_users_firebase_uid ON users(firebase_uid);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id);
        `);
        console.log('✅ Índices creados/verificados');
        
        // Crear función para actualizar updated_at
        await client.query(`
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ language 'plpgsql';
        `);
        
        // Crear triggers para updated_at
        await client.query(`
            DROP TRIGGER IF EXISTS update_users_updated_at ON users;
            CREATE TRIGGER update_users_updated_at 
                BEFORE UPDATE ON users 
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        `);
        
        await client.query(`
            DROP TRIGGER IF EXISTS update_user_profiles_updated_at ON user_profiles;
            CREATE TRIGGER update_user_profiles_updated_at 
                BEFORE UPDATE ON user_profiles 
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        `);
        console.log('✅ Triggers de updated_at creados');
        
        console.log('\n🎉 Base de datos configurada exitosamente!');
        console.log('📊 Tablas creadas:');
        console.log('   - roles');
        console.log('   - users');
        console.log('   - user_profiles');
        console.log('\n💡 Ahora puedes ejecutar: npm start');
        
    } catch (error) {
        console.error('❌ Error al crear las tablas:', error.message);
        console.error('🔍 Verifica:');
        console.error('   - Tu conexión a internet');
        console.error('   - Las credenciales en tu archivo .env');
        console.error('   - Que tu proyecto de Supabase esté activo');
        process.exit(1);
    } finally {
        if (client) {
            client.release();
            await pool.end();
        }
    }
};

// Ejecutar si se llama directamente
if (require.main === module) {
    createTables();
}

module.exports = { createTables };
