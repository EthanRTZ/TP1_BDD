const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');
const bcrypt = require('bcrypt');

// Middleware d'authentification et de permission appliqué à toutes les routes
// C'est une bonne pratique, mais vous pouvez aussi les appliquer route par route.
// router.use(requireAuth);

// Helper pour formater la sortie de l'utilisateur (réutilise la logique de Task 7)
const fetchUserWithRoles = async (id) => {
    const result = await pool.query(
        `SELECT
            u.id,
            u.email,
            u.nom,
            u.prenom,
            u.actif,
            u.date_creation,
            array_agg(r.nom) AS roles
         FROM utilisateurs u
         LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
         LEFT JOIN roles r ON ur.role_id = r.id
         WHERE u.id = $1
         GROUP BY u.id`,
        [id]
    );
    return result.rows[0];
};

// GET /api/users - Lister tous les utilisateurs (Task 19)
router.get('/',
    requireAuth,
    requirePermission('users', 'read'),
    async (req, res) => {
        const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
        const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
        const offset = (page - 1) * limit;

        try {
            const [usersResult, countResult] = await Promise.all([
                pool.query(
                    `SELECT id, email, nom, prenom, actif, date_creation
                     FROM utilisateurs
                     ORDER BY id DESC
                     LIMIT $1 OFFSET $2`,
                    [limit, offset]
                ),
                pool.query('SELECT COUNT(*) AS total FROM utilisateurs')
            ]);

            const total = parseInt(countResult.rows[0].total, 10);
            const totalPages = Math.max(Math.ceil(total / limit), 1);

            res.json({
                pagination: {
                    page,
                    limit,
                    total,
                    totalPages
                },
                users: usersResult.rows
            });
        } catch (error) {
            console.error('Erreur liste utilisateurs:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });

// GET /api/users/:id/permissions - Liste des permissions d'un utilisateur (Task 26)
router.get('/:id/permissions',
    requireAuth,
    requirePermission('users', 'read'),
    async (req, res) => {
        const { id } = req.params;

        try {
            const result = await pool.query(
                `SELECT DISTINCT
                    p.nom,
                    p.ressource,
                    p.action,
                    p.description
                 FROM utilisateurs u
                 INNER JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
                 INNER JOIN role_permissions rp ON rp.role_id = ur.role_id
                 INNER JOIN permissions p ON p.id = rp.permission_id
                 WHERE u.id = $1
                 ORDER BY p.ressource, p.action`,
                [id]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'Utilisateur ou permissions introuvables' });
            }

            res.json({
                utilisateurId: id,
                permissions: result.rows
            });
        } catch (error) {
            console.error('Erreur récupération permissions utilisateur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });

// GET /api/users/:id - Récupérer un utilisateur par ID (Task 20)
router.get('/:id',
    requireAuth,
    requirePermission('users', 'read'),
    async (req, res) => {
        const { id } = req.params;
        try {
            const user = await fetchUserWithRoles(id);

            if (!user) {
                return res.status(404).json({ error: 'Utilisateur non trouvé' });
            }
            res.json({ user });
        } catch (error) {
            console.error('Erreur get utilisateur par ID:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    });

// PUT /api/users/:id - Mettre à jour un utilisateur (Task 21 & 23)
router.put('/:id',
    requireAuth,
    requirePermission('users', 'write'),
    async (req, res) => {
        const { id } = req.params;
        const { nom, prenom, actif, roles, password } = req.body;
        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            // 1. Préparer la mise à jour des champs utilisateurs
            let queryText = `UPDATE utilisateurs SET date_modification = CURRENT_TIMESTAMP`;
            const queryParams = [];
            let paramIndex = 1;

            if (nom !== undefined) {
                queryParams.push(nom);
                queryText += `, nom = $${paramIndex++}`;
            }
            if (prenom !== undefined) {
                queryParams.push(prenom);
                queryText += `, prenom = $${paramIndex++}`;
            }
            // Task 23: Gestion de l'activation/désactivation
            if (actif !== undefined) {
                queryParams.push(actif);
                queryText += `, actif = $${paramIndex++}`;
            }
            if (password) {
                const passwordHash = await bcrypt.hash(password, 10);
                queryParams.push(passwordHash);
                queryText += `, password_hash = $${paramIndex++}`;
            }

            queryText += ` WHERE id = $${paramIndex} RETURNING id`;
            queryParams.push(id);

            const updateResult = await client.query(queryText, queryParams);

            if (updateResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({ error: 'Utilisateur non trouvé' });
            }

            // 2. Mettre à jour les rôles (si fournis)
            if (roles && Array.isArray(roles)) {
                // Suppression des rôles existants
                await client.query('DELETE FROM utilisateur_roles WHERE utilisateur_id = $1', [id]);

                // Insertion des nouveaux rôles
                if (roles.length > 0) {
                    const roleValues = roles.map((roleName, index) => {
                        return `($1, (SELECT id FROM roles WHERE nom = $${index + 2}))`;
                    }).join(', ');

                    const roleNames = roles.map(r => r.toLowerCase());

                    await client.query(
                        `INSERT INTO utilisateur_roles (utilisateur_id, role_id)
                     VALUES ${roleValues}`,
                        [id, ...roleNames]
                    );
                }
            }

            await client.query('COMMIT');

            // Récupérer l'utilisateur mis à jour pour la réponse
            const updatedUser = await fetchUserWithRoles(id);

            res.json({ message: 'Utilisateur mis à jour avec succès', user: updatedUser });

        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Erreur mise à jour utilisateur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        } finally {
            client.release();
        }
    });

// DELETE /api/users/:id - Supprimer un utilisateur (Task 22)
router.delete('/:id',
    requireAuth,
    requirePermission('users', 'delete'),
    async (req, res) => {
        const { id } = req.params;
        const targetId = parseInt(id, 10);

        if (targetId === req.user.utilisateur_id) {
            return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
        }

        const client = await pool.connect();

        try {
            await client.query('BEGIN');

            // Suppression des données liées (roles, sessions, logs)
            await client.query('DELETE FROM utilisateur_roles WHERE utilisateur_id = $1', [id]);
            await client.query('DELETE FROM sessions WHERE utilisateur_id = $1', [id]);
            await client.query('DELETE FROM logs_connexion WHERE utilisateur_id = $1', [id]);

            // Suppression de l'utilisateur
            const result = await client.query(
                `DELETE FROM utilisateurs WHERE id = $1 RETURNING id`,
                [id]
            );

            if (result.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(404).json({ error: 'Utilisateur non trouvé' });
            }

            await client.query('COMMIT');
            res.json({ message: `Utilisateur ID ${id} supprimé avec succès` });

        } catch (error) {
            await client.query('ROLLBACK');
            console.error('Erreur suppression utilisateur:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        } finally {
            client.release();
        }
    });


module.exports = router;