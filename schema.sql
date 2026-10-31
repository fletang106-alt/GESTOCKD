CREATE TABLE IF NOT EXISTS depots (
    id BIGSERIAL PRIMARY KEY,
    nom VARCHAR(150) NOT NULL UNIQUE,
    description TEXT,
    actif BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS utilisateurs (
    id BIGSERIAL PRIMARY KEY,
    nom VARCHAR(150) NOT NULL,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(30) NOT NULL DEFAULT 'utilisateur'
        CHECK (role IN ('administrateur', 'utilisateur')),
    actif BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS produits (
    id BIGSERIAL PRIMARY KEY,
    reference VARCHAR(100) UNIQUE,
    nom VARCHAR(200) NOT NULL,
    categorie VARCHAR(150),
    unite VARCHAR(50) DEFAULT 'unité',
    stock_minimum NUMERIC(14,2) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clients (
    id BIGSERIAL PRIMARY KEY,
    nom VARCHAR(200) NOT NULL,
    telephone VARCHAR(50),
    adresse TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS entrees_stock (
    id BIGSERIAL PRIMARY KEY,
    date_entree DATE NOT NULL DEFAULT CURRENT_DATE,
    produit_id BIGINT NOT NULL REFERENCES produits(id),
    depot_id BIGINT NOT NULL REFERENCES depots(id),
    quantite NUMERIC(14,2) NOT NULL CHECK (quantite > 0),
    fournisseur VARCHAR(200),
    reference_document VARCHAR(150),
    date_expiration DATE,
    observations TEXT,
    utilisateur_id BIGINT REFERENCES utilisateurs(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sorties_stock (
    id BIGSERIAL PRIMARY KEY,
    date_sortie DATE NOT NULL DEFAULT CURRENT_DATE,
    produit_id BIGINT NOT NULL REFERENCES produits(id),
    depot_id BIGINT NOT NULL REFERENCES depots(id),
    client_id BIGINT REFERENCES clients(id),
    quantite_facture NUMERIC(14,2) NOT NULL CHECK (quantite_facture >= 0),
    avance NUMERIC(14,2) NOT NULL CHECK (avance >= 0),
    balance NUMERIC(14,2) GENERATED ALWAYS AS
        (quantite_facture - avance) STORED,
    chauffeur VARCHAR(150),
    plaque VARCHAR(80),
    numero_bon_livraison VARCHAR(150),
    telephone_chauffeur VARCHAR(50),
    observations TEXT,
    utilisateur_id BIGINT REFERENCES utilisateurs(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CHECK (avance <= quantite_facture)
);

CREATE TABLE IF NOT EXISTS ajustements_stock (
    id BIGSERIAL PRIMARY KEY,
    produit_id BIGINT NOT NULL REFERENCES produits(id),
    depot_id BIGINT NOT NULL REFERENCES depots(id),
    quantite_avant NUMERIC(14,2) NOT NULL,
    quantite_apres NUMERIC(14,2) NOT NULL,
    motif TEXT NOT NULL,
    observations TEXT,
    utilisateur_id BIGINT REFERENCES utilisateurs(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_entrees_produit_depot
ON entrees_stock(produit_id, depot_id);

CREATE INDEX IF NOT EXISTS idx_sorties_produit_depot
ON sorties_stock(produit_id, depot_id);

CREATE INDEX IF NOT EXISTS idx_ajustements_produit_depot
ON ajustements_stock(produit_id, depot_id);

INSERT INTO depots (nom)
VALUES ('Dépôt principal')
ON CONFLICT (nom) DO NOTHING;
CREATE TABLE IF NOT EXISTS sessions (
    id BIGSERIAL PRIMARY KEY,
    utilisateur_id BIGINT NOT NULL
        REFERENCES utilisateurs(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expire_le TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_token
ON sessions(token_hash);
