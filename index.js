const express = require('express');
const pool = require('./database/db');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

/**
 * Middlewares globaux
 */
app.use(express.json());

/**
 * Routes principales
 */
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

/**
 * Route racine - permet de vérifier rapidement que l'API répond
 */
app.get('/', (req, res) => {
    res.json({ message: 'API de gestion des utilisateurs opérationnelle' });
});

/**
 * Endpoint de health-check : vérifie la disponibilité de la base
 */
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT NOW()');
        res.status(200).json({ status: 'ok', database: 'connected' });
    } catch (error) {
        console.error('Database connection failed:', error);
        res.status(503).json({ status: 'error', database: 'disconnected' });
    }
});

/**
 * Démarrage du serveur HTTP
 */
app.listen(PORT, () => {
    console.log(`Serveur démarré sur http://localhost:${PORT}`);
});

