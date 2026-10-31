import { neon } from "@neondatabase/serverless";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const sql = neon(process.env.DATABASE_URL);

const hash = (password) =>
  createHash("sha256").update(password).digest("hex");

function token() {
  return randomBytes(32).toString("hex");
}

function unauthorized(res) {
  return res.status(401).json({ error: "Accès non autorisé." });
}

function adminOnly(user, res) {
  if (!user || user.role !== "administrateur") {
    res.status(403).json({ error: "Accès réservé à l'administrateur." });
    return false;
  }
  return true;
}

async function authenticate(req) {
  const value = req.headers.authorization || "";
  const key = value.startsWith("Bearer ") ? value.slice(7) : "";
  if (!key) return null;

  const rows = await sql`
    SELECT u.id, u.nom, u.username, u.role
    FROM sessions s
    JOIN utilisateurs u ON u.id = s.utilisateur_id
    WHERE s.token_hash = ${hash(key)}
      AND s.expire_le > NOW()
      AND u.actif = TRUE
    LIMIT 1
  `;
  return rows[0] || null;
}

export default async function handler(req, res) {
  try {
    if (!process.env.DATABASE_URL) {
      return res.status(500).json({ error: "DATABASE_URL manquant." });
    }

    const route = (req.query.path || []).join("/");
    const method = req.method;

    if (route === "login" && method === "POST") {
      const { username, password } = req.body || {};
      if (!username || !password) {
        return res.status(400).json({ error: "Identifiants requis." });
      }

      const users = await sql`
        SELECT id, nom, username, password_hash, role
        FROM utilisateurs
        WHERE username = ${username}
          AND actif = TRUE
        LIMIT 1
      `;

      const user = users[0];
      if (!user || user.password_hash !== hash(password)) {
        return unauthorized(res);
      }

      const sessionToken = token();
      await sql`
        INSERT INTO sessions (utilisateur_id, token_hash, expire_le)
        VALUES (${user.id}, ${hash(sessionToken)}, NOW() + INTERVAL '7 days')
      `;

      return res.status(200).json({
        token: sessionToken,
        user: {
          id: user.id,
          nom: user.nom,
          username: user.username,
          role: user.role
        }
      });
    }

    const user = await authenticate(req);
    if (!user) return unauthorized(res);

    if (route === "me" && method === "GET") {
      return res.status(200).json({ user });
    }

    if (route === "produits" && method === "GET") {
      const rows = await sql`SELECT * FROM produits ORDER BY nom`;
      return res.status(200).json(rows);
    }

    if (route === "produits" && method === "POST") {
      if (!adminOnly(user, res)) return;
      const { reference, nom, categorie, unite, stock_minimum } = req.body || {};
      if (!nom) return res.status(400).json({ error: "Nom requis." });

      const rows = await sql`
        INSERT INTO produits (reference, nom, categorie, unite, stock_minimum)
        VALUES (${reference || null}, ${nom}, ${categorie || null},
                ${unite || "unité"}, ${Number(stock_minimum) || 0})
        RETURNING *
      `;
      return res.status(201).json(rows[0]);
    }

    if (route === "clients" && method === "GET") {
      const rows = await sql`SELECT * FROM clients ORDER BY nom`;
      return res.status(200).json(rows);
    }

    if (route === "clients" && method === "POST") {
      if (!adminOnly(user, res)) return;
      const { nom, telephone, adresse } = req.body || {};
      if (!nom) return res.status(400).json({ error: "Nom requis." });
      const rows = await sql`
        INSERT INTO clients (nom, telephone, adresse)
        VALUES (${nom}, ${telephone || null}, ${adresse || null})
        RETURNING *
      `;
      return res.status(201).json(rows[0]);
    }

    if (route === "depots" && method === "GET") {
      const rows = await sql`SELECT * FROM depots WHERE actif = TRUE ORDER BY nom`;
      return res.status(200).json(rows);
    }

    if (route === "entrees" && method === "GET") {
      if (!adminOnly(user, res)) return;
      const rows = await sql`
        SELECT e.*, p.nom AS produit, d.nom AS depot
        FROM entrees_stock e
        JOIN produits p ON p.id = e.produit_id
        JOIN depots d ON d.id = e.depot_id
        ORDER BY e.date_entree DESC, e.id DESC
      `;
      return res.status(200).json(rows);
    }

    if (route === "entrees" && method === "POST") {
      const b = req.body || {};
      const quantite = Number(b.quantite);
      if (!b.produit_id || !b.depot_id || !Number.isFinite(quantite) || quantite <= 0) {
        return res.status(400).json({ error: "Données d'entrée invalides." });
      }
      const rows = await sql`
        INSERT INTO entrees_stock
          (date_entree, produit_id, depot_id, quantite, fournisseur,
           reference_document, date_expiration, observations, utilisateur_id)
        VALUES
          (${b.date_entree || null}, ${b.produit_id}, ${b.depot_id}, ${quantite},
           ${b.fournisseur || null}, ${b.reference_document || null},
           ${b.date_expiration || null}, ${b.observations || null}, ${user.id})
        RETURNING *
      `;
      return res.status(201).json(rows[0]);
    }

    if (route === "sorties" && method === "POST") {
      const b = req.body || {};
      const facture = Number(b.quantite_facture);
      const avance = Number(b.avance);
      if (!b.produit_id || !b.depot_id ||
          !Number.isFinite(facture) || !Number.isFinite(avance) ||
          facture < 0 || avance < 0 || avance > facture) {
        return res.status(400).json({ error: "Données de sortie invalides." });
      }

      const rows = await sql`
        INSERT INTO sorties_stock
          (date_sortie, produit_id, depot_id, client_id, quantite_facture,
           avance, chauffeur, plaque, numero_bon_livraison,
           telephone_chauffeur, observations, utilisateur_id)
        VALUES
          (${b.date_sortie || null}, ${b.produit_id}, ${b.depot_id},
           ${b.client_id || null}, ${facture}, ${avance},
           ${b.chauffeur || null}, ${b.plaque || null},
           ${b.numero_bon_livraison || null}, ${b.telephone_chauffeur || null},
           ${b.observations || null}, ${user.id})
        RETURNING *
      `;
      return res.status(201).json(rows[0]);
    }

    if (route === "stock" && method === "GET") {
      const rows = await sql`
        SELECT p.id AS produit_id, p.nom AS produit,
               d.id AS depot_id, d.nom AS depot,
               COALESCE(e.total_entrees, 0) - COALESCE(s.total_sorties, 0) AS stock
        FROM produits p
        CROSS JOIN depots d
        LEFT JOIN (
          SELECT produit_id, depot_id, SUM(quantite) AS total_entrees
          FROM entrees_stock GROUP BY produit_id, depot_id
        ) e ON e.produit_id = p.id AND e.depot_id = d.id
        LEFT JOIN (
          SELECT produit_id, depot_id, SUM(avance) AS total_sorties
          FROM sorties_stock GROUP BY produit_id, depot_id
        ) s ON s.produit_id = p.id AND s.depot_id = d.id
        WHERE d.actif = TRUE
        ORDER BY p.nom, d.nom
      `;
      return res.status(200).json(rows);
    }

    if (route === "sorties" && method === "GET") {
      if (!adminOnly(user, res)) return;
      const rows = await sql`
        SELECT s.*, p.nom AS produit, d.nom AS depot, c.nom AS client
        FROM sorties_stock s
        JOIN produits p ON p.id = s.produit_id
        JOIN depots d ON d.id = s.depot_id
        LEFT JOIN clients c ON c.id = s.client_id
        ORDER BY s.date_sortie DESC, s.id DESC
      `;
      return res.status(200).json(rows);
    }

    if (route === "utilisateurs" && method === "GET") {
      if (!adminOnly(user, res)) return;
      const rows = await sql`
        SELECT id, nom, username, role, actif
        FROM utilisateurs ORDER BY nom
      `;
      return res.status(200).json(rows);
    }

    if (route === "utilisateurs" && method === "POST") {
      if (!adminOnly(user, res)) return;
      const b = req.body || {};
      if (!b.nom || !b.username || !b.password ||
          !["administrateur", "utilisateur"].includes(b.role)) {
        return res.status(400).json({ error: "Informations utilisateur invalides." });
      }
      const rows = await sql`
        INSERT INTO utilisateurs (nom, username, password_hash, role)
        VALUES (${b.nom}, ${b.username}, ${hash(b.password)}, ${b.role})
        RETURNING id, nom, username, role, actif
      `;
      return res.status(201).json(rows[0]);
    }

    if (route === "historique" && method === "GET") {
      if (!adminOnly(user, res)) return;
      const [entrees, sorties, ajustements] = await Promise.all([
        sql`SELECT * FROM entrees_stock ORDER BY created_at DESC`,
        sql`SELECT * FROM sorties_stock ORDER BY created_at DESC`,
        sql`SELECT * FROM ajustements_stock ORDER BY created_at DESC`
      ]);
      return res.status(200).json({ entrees, sorties, ajustements });
    }

    return res.status(404).json({ error: "Route introuvable." });
  } catch (error) {
    console.error("GESTOCKD API:", error);
    return res.status(500).json({ error: "Erreur serveur. Vérifiez les données et la base Neon." });
  }
}
