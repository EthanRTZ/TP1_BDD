DROP TABLE IF EXISTS logs_connexion;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS utilisateur_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS utilisateurs;

CREATE TABLE utilisateurs (
                              id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                              email VARCHAR(255) NOT NULL UNIQUE,
                              password_hash TEXT NOT NULL,
                              nom VARCHAR(100),
                              prenom VARCHAR(100),
                              actif BOOLEAN NOT NULL DEFAULT TRUE,
                              date_creation TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
                              date_modification TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX idx_utilisateurs_email ON utilisateurs(email);
CREATE INDEX idx_utilisateurs_actif ON utilisateurs(actif);

CREATE TABLE roles (
                       id SERIAL PRIMARY KEY,
                       nom VARCHAR(100) UNIQUE NOT NULL,
                       description TEXT,
                       date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permissions (
                             id SERIAL PRIMARY KEY,
                             nom VARCHAR(100) UNIQUE NOT NULL,
                             ressource VARCHAR(100) NOT NULL,
                             action VARCHAR(100) NOT NULL,
                             description TEXT,
                             CONSTRAINT unique_permission UNIQUE (ressource, action)
);

CREATE TABLE utilisateur_roles (
                                   utilisateur_id INT REFERENCES utilisateurs(id) ON DELETE CASCADE,
                                   role_id INT REFERENCES roles(id) ON DELETE CASCADE,
                                   date_assignation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                   PRIMARY KEY (utilisateur_id, role_id)
);

CREATE TABLE role_permissions (
                                  role_id INT REFERENCES roles(id) ON DELETE CASCADE,
                                  permission_id INT REFERENCES permissions(id) ON DELETE CASCADE,
                                  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE sessions (
                          id SERIAL PRIMARY KEY,
                          utilisateur_id INT REFERENCES utilisateurs(id) ON DELETE CASCADE,
                          token UUID UNIQUE NOT NULL,
                          date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                          date_expiration TIMESTAMP,
                          actif BOOLEAN DEFAULT true
);
CREATE TABLE logs_connexion (
                                id SERIAL PRIMARY KEY,
                                utilisateur_id INT REFERENCES utilisateurs(id),
                                email_tentative VARCHAR(255),
                                date_heure TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                adresse_ip VARCHAR(100),
                                user_agent TEXT,
                                succes BOOLEAN,
                                message TEXT
);

INSERT INTO roles (nom, description) VALUES
                                         ('admin', 'Administrateur'),
                                         ('moderator', 'Modérateur'),
                                         ('user', 'Utilisateur standard')
ON CONFLICT (nom) DO NOTHING;

INSERT INTO permissions (nom, ressource, action, description) VALUES
                                                                  ('read_users', 'users', 'read', 'Lire les utilisateurs'),
                                                                  ('write_users', 'users', 'write', 'Créer/éditer utilisateurs'),
                                                                  ('delete_users', 'users', 'delete', 'Supprimer utilisateurs'),
                                                                  ('read_posts', 'posts', 'read', 'Lire posts'),
                                                                  ('write_posts', 'posts', 'write', 'Créer/éditer posts'),
                                                                  ('delete_posts', 'posts', 'delete', 'Supprimer posts')
ON CONFLICT (nom) DO NOTHING;

-- Admin = toutes les permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT (SELECT id FROM roles WHERE nom='admin'), id FROM permissions;

-- Moderator
INSERT INTO role_permissions (role_id, permission_id)
SELECT (SELECT id FROM roles WHERE nom='moderator'), id FROM permissions
WHERE nom IN ('read_users', 'read_posts', 'write_posts', 'delete_posts');

-- User
INSERT INTO role_permissions (role_id, permission_id)
SELECT (SELECT id FROM roles WHERE nom='user'), id FROM permissions
WHERE nom IN ('read_users', 'read_posts', 'write_posts');

-- Admin = toutes les permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT (SELECT id FROM roles WHERE nom='admin'), id FROM permissions
ON CONFLICT DO NOTHING;


-- Moderator
INSERT INTO role_permissions (role_id, permission_id)
SELECT
    (SELECT id FROM roles WHERE nom='moderator'),
    id
FROM permissions
WHERE nom IN ('read_users', 'read_posts', 'write_posts', 'delete_posts')
ON CONFLICT DO NOTHING;


-- User
INSERT INTO role_permissions (role_id, permission_id)
SELECT (SELECT id FROM roles WHERE nom='user'), id
FROM permissions
WHERE nom IN ('read_users', 'read_posts', 'write_posts')
ON CONFLICT DO NOTHING;



CREATE OR REPLACE FUNCTION utilisateur_a_permission(
    p_utilisateur_id INT,
    p_ressource VARCHAR,
    p_action VARCHAR
)
    RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM utilisateurs u
                 JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
                 JOIN role_permissions rp ON rp.role_id = ur.role_id
                 JOIN permissions p ON p.id = rp.permission_id
        WHERE u.id = p_utilisateur_id
          AND u.actif = true
          AND p.ressource = p_ressource
          AND p.action = p_action
    );
END;
$$ LANGUAGE plpgsql;

SELECT
    u.id,
    u.email,
    u.nom,
    u.prenom,
    u.actif,
    array_agg(r.nom) AS roles
FROM
    utilisateurs u
        LEFT JOIN
    utilisateur_roles ur ON u.id = ur.utilisateur_id
        LEFT JOIN
    roles r ON ur.role_id = r.id
WHERE
    u.id = 1
GROUP BY
    u.id;

SELECT DISTINCT
    u.id AS utilisateur_id,
    u.email,
    p.nom AS permission,
    p.ressource,
    p.action
FROM
    utilisateurs u
        INNER JOIN
    utilisateur_roles ur ON u.id = ur.utilisateur_id
        INNER JOIN
    roles r ON ur.role_id = r.id
        INNER JOIN
    role_permissions rp ON r.id = rp.role_id
        INNER JOIN
    permissions p ON rp.permission_id = p.id
WHERE
    u.id = 1
ORDER BY
    p.ressource, p.action;

SELECT
    r.nom AS nom_role,
    COUNT(ur.utilisateur_id) AS nombre_utilisateurs
FROM
    roles r
        LEFT JOIN
    utilisateur_roles ur ON r.id = ur.role_id
GROUP BY
    r.nom
ORDER BY
    nombre_utilisateurs DESC;

SELECT
    u.id,
    u.email,
    array_agg(r.nom) AS roles
FROM
    utilisateurs u
        INNER JOIN
    utilisateur_roles ur ON u.id = ur.utilisateur_id
        INNER JOIN
    roles r ON ur.role_id = r.id
WHERE
    r.nom IN ('admin', 'moderator')
GROUP BY
    u.id, u.email
HAVING
    COUNT(DISTINCT r.nom) = 2;

SELECT
    DATE(date_heure) AS jour,
    COUNT(*) AS tentatives_echouees
FROM
    logs_connexion
WHERE
    succes = false
  AND date_heure >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY
    DATE(date_heure)
ORDER BY
    jour DESC;