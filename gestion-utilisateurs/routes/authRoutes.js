const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const { requireAuth } = require('../middleware/auth');

// POST /api/auth/register (Task 14)
router.post('/register', async (req, res) => {
    const { email, password, nom, prenom } = req.body;

    // 1. Validation
    if (!email || !password) {
        return res.status(400).json({ error: 'Email et mot de passe requis' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 2. Vérifier si email existe
        const checkUser = await client.query(
            'SELECT id FROM utilisateurs WHERE email = $1',
            [email]
        );

        if (checkUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ error: 'Email déjà utilisé' });
        }

        // 3. Hasher le mot de passe
        const passwordHash = await bcrypt.hash(password, 10);

        // 4. Insérer l'utilisateur
        const result = await client.query(
            `INSERT INTO utilisateurs (email, password_hash, nom, prenom)
             VALUES ($1, $2, $3, $4)
             RETURNING id, email, nom, prenom, date_creation`,
            [email, passwordHash, nom, prenom]
        );

        const newUser = result.rows[0];

        // 5. Assigner le rôle "user" par défaut
        await client.query(
            `INSERT INTO utilisateur_roles (utilisateur_id, role_id)
             SELECT $1, id FROM roles WHERE nom = 'user'`,
            [newUser.id]
        );

        // 6. COMMIT la transaction
        await client.query('COMMIT');

        // 7. Retourner l'utilisateur créé
        res.status(201).json({
            message: 'Utilisateur créé avec succès',
            user: newUser
        });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erreur création utilisateur:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    } finally {
        client.release();
    }
});

// POST /api/auth/login (Task 15)
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const client = await pool.connect();
    // Ces informations ne sont pas dans l'énoncé, mais nécessaires pour les logs (Task 15 / 6)
    const logIp = req.ip || '::1';
    const logUserAgent = req.headers['user-agent'] || 'Unknown';
    let user = null;

    try {
        await client.query('BEGIN');

        // 1. Récupérer l'utilisateur
        const userResult = await client.query(
            `SELECT id, email, password_hash, nom, prenom, actif FROM utilisateurs WHERE email = $1`,
            [email]
        );

        if (userResult.rows.length === 0) {
            // Logger l'échec (Email inexistant)
            await client.query(
                `INSERT INTO logs_connexion (email_tentative, succes, message, adresse_ip, user_agent)
                 VALUES ($1, false, $2, $3, $4)`,
                [email, 'Email inexistant', logIp, logUserAgent]
            );
            await client.query('COMMIT');
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        user = userResult.rows[0];

        // 2. Vérifier si actif
        if (!user.actif) {
            // Logger l'échec (Compte désactivé)
            await client.query(
                `INSERT INTO logs_connexion (utilisateur_id, email_tentative, succes, message, adresse_ip, user_agent)
                 VALUES ($1, $2, false, $3, $4, $5)`,
                [user.id, email, 'Compte désactivé', logIp, logUserAgent]
            );
            await client.query('COMMIT');
            return res.status(403).json({ error: 'Compte désactivé' });
        }

        // 3. Vérifier le mot de passe
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            // Logger l'échec (Mot de passe invalide)
            await client.query(
                `INSERT INTO logs_connexion (utilisateur_id, email_tentative, succes, message, adresse_ip, user_agent)
                 VALUES ($1, $2, false, $3, $4, $5)`,
                [user.id, email, 'Mot de passe invalide', logIp, logUserAgent]
            );
            await client.query('COMMIT');
            return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        }

        // 4. Générer token
        const token = uuidv4();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 24);

        // 5. Créer session
        await client.query(
            `INSERT INTO sessions (utilisateur_id, token, date_expiration)
             VALUES ($1, $2, $3)`,
            [user.id, token, expiresAt]
        );

        // 6. Logger succès
        await client.query(
            `INSERT INTO logs_connexion (utilisateur_id, email_tentative, succes, message, adresse_ip, user_agent)
             VALUES ($1, $2, true, $3, $4, $5)`,
            [user.id, email, 'Connexion réussie', logIp, logUserAgent]
        );

        await client.query('COMMIT');

        // 7. Retourner le token et les infos utilisateur
        res.json({
            message: 'Connexion réussie',
            token: token,
            user: {
                id: user.id,
                email: user.email,
                nom: user.nom,
                prenom: user.prenom
            },
            expiresAt: expiresAt
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erreur login:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    } finally {
        client.release();
    }
});

// GET /api/auth/profile (Task 17)
router.get('/profile', requireAuth, async (req, res) => {
    try {
        // Récupérer l'utilisateur avec ses rôles (Réutilise la logique de Task 7)
        const result = await pool.query(
            `SELECT
                u.id,
                u.email,
                u.nom,
                u.prenom,
                array_agg(r.nom) AS roles
             FROM utilisateurs u
             LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
             LEFT JOIN roles r ON ur.role_id = r.id
             WHERE u.id = $1
             GROUP BY u.id`,
            [req.user.utilisateur_id]
        );
        res.json({ user: result.rows[0] });
    } catch (error) {
        console.error('Erreur profil:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// POST /api/auth/logout (Task 24)
router.post('/logout', requireAuth, async (req, res) => {
    const token = req.token; // Le token est stocké dans req.token par le middleware requireAuth
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // 1. Désactiver la session
        const result = await client.query(
            `UPDATE sessions
             SET actif = false
             WHERE token = $1 AND actif = true
             RETURNING utilisateur_id`,
            [token]
        );

        if (result.rows.length > 0) {
            const userId = result.rows[0].utilisateur_id;

            // 2. Logger la déconnexion dans logs_connexion
            await client.query(
                `INSERT INTO logs_connexion
                 (utilisateur_id, email_tentative, succes, message)
                 VALUES ($1, $2, true, 'Déconnexion réussie')`,
                [userId, req.user.email]
            );
        }

        await client.query('COMMIT');
        res.json({ message: 'Déconnexion réussie' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Erreur logout:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    } finally {
        client.release();
    }
});

// GET /api/auth/logs (Task 25)
router.get('/logs', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT date_heure, email_tentative, adresse_ip, user_agent, succes, message
             FROM logs_connexion
             WHERE utilisateur_id = $1
             ORDER BY date_heure DESC
             LIMIT 50`,
            [req.user.utilisateur_id]
        );
        res.json({ logs: result.rows });
    } catch (error) {
        console.error('Erreur logs:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});


module.exports = router;