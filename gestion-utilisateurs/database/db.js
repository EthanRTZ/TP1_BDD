const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
    user: process.env.DB_USER,       // nom d'utilisateur PostgreSQL
    host: process.env.DB_HOST,       // hôte de la base de données
    database: process.env.DB_NAME,   // nom de la base de données
    password: process.env.DB_PASSWORD, // mot de passe
    port: process.env.DB_PORT,       // port PostgreSQL (par défaut 5432)
});

pool.on('connect', () => {
    console.log('✅ Connecté à PostgreSQL');
});

pool.on('error', (err) => {
    console.error('❌ Erreur PostgreSQL:', err);
});

module.exports = pool;
