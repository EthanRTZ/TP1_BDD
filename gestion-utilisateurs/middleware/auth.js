const pool = require('../database/db'); // [cite: 312]

async function requireAuth(req, res, next) { // [cite: 313]
    const authHeader = req.headers['authorization'];

    // Vérifier si le token est présent et au format "Bearer <token>"
    if (!authHeader || !authHeader.startsWith('Bearer ')) { // [cite: 314]
        return res.status(401).json({ error: 'Token manquant ou format invalide' }); // [cite: 344]
    }

    // Extraire le token (supprime "Bearer ")
    const token = authHeader.substring(7);

    try {
        // Vérifier que le token est valide et récupérer les infos utilisateur
        const result = await pool.query(
            `SELECT 
                 u.id AS utilisateur_id,
                 u.email,
                 u.nom,
                 u.prenom
             FROM sessions s
             INNER JOIN utilisateurs u ON s.utilisateur_id = u.id
             WHERE s.token = $1
               AND s.actif = true
               AND s.date_expiration > CURRENT_TIMESTAMP
               AND u.actif = true`, // [cite: 319, 346]
            [token]
        );

        if (result.rows.length === 0) { // [cite: 320]
            // Marquer le token comme non valide (session expirée ou inactive)
            return res.status(401).json({ error: 'Token invalide ou expiré' }); // [cite: 346]
        }

        // Ajouter les infos utilisateur à l'objet req pour les routes suivantes
        req.user = result.rows[0]; // [cite: 320]
        req.token = token; // Ajout du token à req pour la déconnexion
        next(); // [cite: 320]
    } catch (error) {
        console.error('Erreur middleware auth:', error); // [cite: 321]
        res.status(500).json({ error: 'Erreur serveur' }); // [cite: 321]
    }
}

// Exercice 3.8 - Task 18 (BONUS)
function requirePermission(ressource, action) { // [cite: 325]
    return async (req, res, next) => { // [cite: 325]
        try {
            const result = await pool.query(
                'SELECT utilisateur_a_permission($1, $2, $3) AS a_permission', // [cite: 325]
                [req.user.utilisateur_id, ressource, action] // [cite: 325]
            );

            if (!result.rows[0].a_permission) { // [cite: 325]
                return res.status(403).json({ error: 'Permission refusée' }); // [cite: 325]
            }
            next(); // [cite: 325]
        } catch (error) { // [cite: 326]
            console.error('Erreur vérification permission:', error); // [cite: 326]
            res.status(500).json({ error: 'Erreur serveur' }); // [cite: 326]
        }
    };
}

module.exports = { requireAuth, requirePermission }; // [cite: 322, 326]