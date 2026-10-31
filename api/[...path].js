import { neon } from "@neondatabase/serverless";
import crypto from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(crypto.scrypt);
const sql = neon(process.env.DATABASE_URL);

const send = (res, status, data) => res.status(status).json(data);
const hashPassword = async password => {
  const salt = crypto.randomBytes(16).toString("hex");
  const key = await scrypt(password, salt, 64);
  return `${salt}:${key.toString("hex")}`;
};
const verifyPassword = async (password, stored) => {
  if (!stored || !stored.includes(":")) return false;
  const [salt, saved] = stored.split(":");
  const key = await scrypt(password, salt, 64);
  const buffer = Buffer.from(saved, "hex");
  return buffer.length === key.length && crypto.timingSafeEqual(key, buffer);
};
const tokenHash = token =>
  crypto.createHash("sha256").update(token).digest("hex");
const required = value =>
  value !== undefined && value !== null && String(value).trim() !== "";
const adminOnly = user => user?.role === "administrateur";

async function getUser(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return null;

  const rows = await sql`
    SELECT u.id, u.nom, u.username, u.role
    FROM sessions s
    JOIN utilisateurs u ON u.id = s.utilisateur_id
    WHERE s.token_hash = ${tokenHash(token)}
      AND s.expire_le > NOW()
      AND u.actif = TRUE
    LIMIT 1
  `;
  return rows[0] || null;
}

async function createFirstAdmin() {
  const existing = await sql`SELECT id FROM utilisateurs LIMIT 1`;
  if (existing.length) return;

  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;
  const nom = process.env.ADMIN_NAME || "Administrateur";

  if (!username || !password) {
    throw new Error("Configurez ADMIN_USERNAME et ADMIN_PASSWORD dans Vercel.");
  }

  const passwordHash = await hashPassword(password);
  await sql`
    INSERT INTO utilisateurs (nom, username, password_hash, role)
    VALUES (${nom}, ${username}, ${passwordHash}, 'administrateur')
    ON CONFLICT (username) DO NOTHING
  `;
}

export default async function handler(req, res) {
  try {
    if (!process.env.DATABASE_URL) {
      return send(res, 500, { error: "DATABASE_URL manquant dans Vercel." });
    }

    const path = new URL(req.url, "https://gestockd.app").pathname
      .replace(/^\/api\/?/, "").replace(/\/$/, "");
    const parts = path.split("/").filter(Boolean);
    const route = parts[0] || "";
    const id = parts[1] || "";

    if (route === "login" && req.method === "POST") {
      const { username, password } = req.body || {};
      if (!required(username) || !required(password)) {
        return send(res, 400, { error: "Identifiant et mot de passe obligatoires." });
      }

      await createFirstAdmin();

      const rows = await sql`
        SELECT id, nom, username, password_hash, role
        FROM utilisateurs
        WHERE username = ${String(username).trim()} AND actif = TRUE
        LIMIT 1
      `;
      const user = rows[0];

      if (!user || !(await verifyPassword(String(password), user.password_hash))) {
        return send(res, 401, { error: "Identifiants incorrects." });
      }

      const token = crypto.randomBytes(32).toString("hex");
      const expires = new Date(Date.now() + 7 * 86400000);

      await sql`
        INSERT INTO sessions (utilisateur_id, token_hash, expire_le)
        VALUES (${user.id}, ${tokenHash(token)}, ${expires.toISOString()})
      `;

      return send(res, 200, {
        token,
        user: {
          id: user.id, nom: user.nom,
          username: user.username, role: user.role
        }
      });
    }

    const user = await getUser(req);
    if (!user) {
      return send(res, 401, { error: "Session invalide ou expirée. Reconnectez-vous." });
    }

    if (route === "me" && req.method === "GET") {
      return send(res, 200, { user });
    }

    if (route === "logout" && req.method === "POST") {
      const token = (req.headers.authorization || "").replace(/^Bearer /, "");
      if (token) {
        await sql`DELETE FROM sessions WHERE token_hash = ${tokenHash(token)}`;
      }
      return send(res, 200, { message: "Déconnexion réussie." });
    }

    // PRODUITS
    if (route === "produits" && parts.length === 1 && req.method === "GET") {
      return send(res, 200, await sql`
        SELECT id, reference, nom, categorie, unite, stock_minimum
        FROM produits ORDER BY nom
      `);
    }

    if (route === "produits" && parts.length === 1 && req.method === "POST") {
      if (!adminOnly(user)) return send(res, 403, { error: "Réservé à l'administrateur." });
      const b = req.body || {};
      if (!required(b.nom)) return send(res, 400, { error: "Nom du produit obligatoire." });

      const rows = await sql`
        INSERT INTO produits (nom, reference, categorie, unite, stock_minimum)
        VALUES (${b.nom}, ${b.reference || null}, ${b.categorie || null},
          ${b.unite || "unité"}, ${Number(b.stock_minimum || 0)})
        RETURNING *
      `;
      return send(res, 201, rows[0]);
    }

    if (route === "produits" && id && req.method === "PATCH") {
      if (!adminOnly(user)) return send(res, 403, { error: "Réservé à l'administrateur." });
      const b = req.body || {};
      if (!required(b.nom)) return send(res, 400, { error: "Nom du produit obligatoire." });

      const rows = await sql`
        UPDATE produits SET
          nom = ${b.nom},
          reference = ${b.reference || null},
          categorie = ${b.categorie || null},
          unite = ${b.unite || "unité"},
          stock_minimum = ${Number(b.stock_minimum || 0)}
        WHERE id = ${id}
        RETURNING *
      `;
      return rows.length ? send(res, 200, rows[0]) :
        send(res, 404, { error: "Produit introuvable." });
    }

    if (route === "produits" && id && req.method === "DELETE") {
      if (!adminOnly(user)) return send(res, 403, { error: "Réservé à l'administrateur." });
      const rows = await sql`DELETE FROM produits WHERE id = ${id} RETURNING id`;
      return rows.length ? send(res, 200, { message: "Produit supprimé." }) :
        send(res, 404, { error: "Produit introuvable." });
    }

    // CLIENTS
    if (route === "clients" && req.method === "GET") {
      return send(res, 200, await sql`SELECT * FROM clients ORDER BY nom`);
    }

    if (route === "clients" && req.method === "POST") {
      if (!adminOnly(user)) return send(res, 403, { error: "Réservé à l'administrateur." });
      const b = req.body || {};
      if (!required(b.nom)) return send(res, 400, { error: "Nom du client obligatoire." });
      const rows = await sql`
        INSERT INTO clients (nom, telephone, adresse)
        VALUES (${b.nom}, ${b.telephone || null}, ${b.adresse || null})
        RETURNING *
      `;
      return send(res, 201, rows[0]);
    }

    // DEPOTS
    if (route === "depots" && parts.length === 1 && req.method === "GET") {
      const rows = adminOnly(user)
        ? await sql`SELECT id, nom, description, actif FROM depots ORDER BY nom`
        : await sql`SELECT id, nom, description, actif FROM depots WHERE actif = TRUE ORDER BY nom`;
      return send(res, 200, rows);
    }

    if (route === "depots" && parts.length === 1 && req.method === "POST") {
      if (!adminOnly(user)) return send(res, 403, { error: "Réservé à l'administrateur." });
      const b = req.body || {};
      if (!required(b.nom)) return send(res, 400, { error: "Nom du dépôt obligatoire." });
      const rows = await sql`
        INSERT INTO depots (nom, description)
        VALUES (${b.nom}, ${b.description || null})
        RETURNING *
      `;
      return send(res, 201, rows[0]);
    }

    if (route === "depots" && id && req.method === "PATCH") {
      if (!adminOnly(user)) return send(res, 403, { error: "Réservé à l'administrateur." });
      const b = req.body || {};
      if (!required(b.nom)) return send(res, 400, { error: "Nom du dépôt obligatoire." });
      const rows = await sql`
        UPDATE depots SET nom = ${b.nom},
          description = ${b.description || null},
          actif = ${b.actif !== false}
        WHERE id = ${id}
        RETURNING *
      `;
      return rows.length ? send(res, 200, rows[0]) :
        send(res, 404, { error: "Dépôt introuvable." });
    }

    if (route === "depots" && id && req.method === "DELETE") {
      if (!adminOnly(user)) return send(res, 403, { error: "Réservé à l'administrateur." });
      const rows = await sql`
        UPDATE depots SET actif = FALSE WHERE id = ${id} RETURNING id
      `;
      return rows.length ? send(res, 200, { message: "Dépôt désactivé." }) :
        send(res, 404, { error: "Dépôt introuvable." });
    }

    // ENTREES
    if (route === "entrees" && req.method === "GET") {
      return send(res, 200, await sql`
        SELECT e.*, p.nom AS produit, d.nom AS depot
        FROM entrees_stock e
        JOIN produits p ON p.id = e.produit_id
        JOIN depots d ON d.id = e.depot_id
        ORDER BY e.date_entree DESC, e.id DESC
      `);
    }

    if (route === "entrees" && req.method === "POST") {
      const b = req.body || {};
      if (!required(b.produit_id) || !required(b.depot_id) ||
          !required(b.quantite) || !Number.isFinite(Number(b.quantite)) ||
          Number(b.quantite) <= 0) {
        return send(res, 400, { error: "Produit, dépôt et quantité positive obligatoires." });
      }

      const depot = await sql`SELECT id FROM depots WHERE id = ${b.depot_id} AND actif = TRUE`;
      if (!depot.length) return send(res, 400, { error: "Dépôt inactif ou inexistant." });

      const rows = await sql`
        INSERT INTO entrees_stock
          (date_entree, produit_id, depot_id, quantite, fournisseur,
           reference_document, date_expiration, observations, utilisateur_id)
        VALUES
          (${b.date_entree || null}, ${b.produit_id}, ${b.depot_id},
           ${Number(b.quantite)}, ${b.fournisseur || null},
           ${b.reference_document || null}, ${b.date_expiration || null},
           ${b.observations || null}, ${user.id})
        RETURNING *
      `;
      return send(res, 201, rows[0]);
    }

    // SORTIES : L'AVANCE DIMINYE LE STOCK
    if (route === "sorties" && req.method === "GET") {
      return send(res, 200, await sql`
        SELECT s.*, p.nom AS produit, d.nom AS depot, c.nom AS client
        FROM sorties_stock s
        JOIN produits p ON p.id = s.produit_id
        JOIN depots d ON d.id = s.depot_id
        LEFT JOIN clients c ON c.id = s.client_id
        ORDER BY s.date_sortie DESC, s.id DESC
      `);
    }

    if (route === "sorties" && req.method === "POST") {
      const b = req.body || {};
      const facture = Number(b.quantite_facture);
      const avance = Number(b.avance);

      if (!required(b.produit_id) || !required(b.depot_id) ||
          !Number.isFinite(facture) || !Number.isFinite(avance) ||
          facture < 0 || avance < 0 || avance > facture) {
        return send(res, 400, { error: "Vérifiez le produit, le dépôt, la facture et l'avance." });
      }

      const depot = await sql`SELECT id FROM depots WHERE id = ${b.depot_id} AND actif = TRUE`;
      if (!depot.length) return send(res, 400, { error: "Dépôt inactif ou inexistant." });

      const stockRows = await sql`
        SELECT
          COALESCE((SELECT SUM(quantite) FROM entrees_stock
            WHERE produit_id = ${b.produit_id} AND depot_id = ${b.depot_id}), 0)
          - COALESCE((SELECT SUM(avance) FROM sorties_stock
            WHERE produit_id = ${b.produit_id} AND depot_id = ${b.depot_id}), 0)
          + COALESCE((SELECT SUM(quantite_apres - quantite_avant)
            FROM ajustements_stock
            WHERE produit_id = ${b.produit_id} AND depot_id = ${b.depot_id}), 0)
          AS disponible
      `;

      if (avance > Number(stockRows[0].disponible)) {
        return send(res, 409, { error: `Stock insuffisant. Disponible : ${stockRows[0].disponible}.` });
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
      return send(res, 201, rows[0]);
    }

    // STOCK PAR PRODUIT ET DEPOT
    if (route === "stock" && req.method === "GET") {
      const rows = await sql`
        SELECT p.id AS produit_id, p.nom AS produit, p.reference, p.unite,
          p.stock_minimum, d.id AS depot_id, d.nom AS depot,
          COALESCE(e.total_entrees, 0) AS total_entrees,
          COALESCE(s.total_sorties, 0) AS total_sorties,
          COALESCE(a.ajustement, 0) AS ajustement,
          COALESCE(e.total_entrees, 0) - COALESCE(s.total_sorties, 0)
            + COALESCE(a.ajustement, 0) AS stock
        FROM produits p CROSS JOIN depots d
        LEFT JOIN (
          SELECT produit_id, depot_id, SUM(quantite) AS total_entrees
          FROM entrees_stock GROUP BY produit_id, depot_id
        ) e ON e.produit_id = p.id AND e.depot_id = d.id
        LEFT JOIN (
          SELECT produit_id, depot_id, SUM(avance) AS total_sorties
          FROM sorties_stock GROUP BY produit_id, depot_id
        ) s ON s.produit_id = p.id AND s.depot_id = d.id
        LEFT JOIN (
          SELECT produit_id, depot_id,
            SUM(quantite_apres - quantite_avant) AS ajustement
          FROM ajustements_stock GROUP BY produit_id, depot_id
        ) a ON a.produit_id = p.id AND a.depot_id = d.id
        WHERE d.actif = TRUE
        ORDER BY p.nom, d.nom
      `;
      return send(res, 200, rows);
    }

    // HISTORIQUE — ADMIN
    if (route === "historique" && req.method === "GET") {
      if (!adminOnly(user)) return send(res, 403, { error: "Accès réservé à l'administrateur." });
      const entrees = await sql`
        SELECT e.*, p.nom AS produit, d.nom AS depot
        FROM entrees_stock e
        JOIN produits p ON p.id = e.produit_id
        JOIN depots d ON d.id = e.depot_id
        ORDER BY e.date_entree DESC
      `;
      const sorties = await sql`
        SELECT s.*, p.nom AS produit, d.nom AS depot, c.nom AS client
        FROM sorties_stock s
        JOIN produits p ON p.id = s.produit_id
        JOIN depots d ON d.id = s.depot_id
        LEFT JOIN clients c ON c.id = s.client_id
        ORDER BY s.date_sortie DESC
      `;
      return send(res, 200, { entrees, sorties });
    }

    // UTILISATEURS — ADMIN
    if (route === "utilisateurs" && req.method === "GET") {
      if (!adminOnly(user)) return send(res, 403, { error: "Accès réservé à l'administrateur." });
      return send(res, 200, await sql`
        SELECT id, nom, username, role, actif, created_at
        FROM utilisateurs ORDER BY nom
      `);
    }

    if (route === "utilisateurs" && req.method === "POST") {
      if (!adminOnly(user)) return send(res, 403, { error: "Accès réservé à l'administrateur." });
      const b = req.body || {};
      if (!required(b.nom) || !required(b.username) || !required(b.password)) {
        return send(res, 400, { error: "Nom, identifiant et mot de passe obligatoires." });
      }
      if (String(b.password).length < 8) {
        return send(res, 400, { error: "Le mot de passe doit contenir 8 caractères minimum." });
      }
      if (!["administrateur", "utilisateur"].includes(b.role)) {
        return send(res, 400, { error: "Rôle invalide." });
      }
      const passwordHash = await hashPassword(String(b.password));
      const rows = await sql`
        INSERT INTO utilisateurs (nom, username, password_hash, role)
        VALUES (${b.nom}, ${b.username}, ${passwordHash}, ${b.role})
        RETURNING id, nom, username, role, actif
      `;
      return send(res, 201, rows[0]);
    }

    // AJUSTEMENTS — ADMIN
    if (route === "ajustements" && req.method === "GET") {
      if (!adminOnly(user)) return send(res, 403, { error: "Accès réservé à l'administrateur." });
      return send(res, 200, await sql`
        SELECT a.*, p.nom AS produit, d.nom AS depot
        FROM ajustements_stock a
        JOIN produits p ON p.id = a.produit_id
        JOIN depots d ON d.id = a.depot_id
        ORDER BY a.created_at DESC
      `);
    }

    if (route === "ajustements" && req.method === "POST") {
      if (!adminOnly(user)) return send(res, 403, { error: "Accès réservé à l'administrateur." });
      const b = req.body || {};
      if (!required(b.produit_id) || !required(b.depot_id) ||
          !required(b.quantite_avant) || !required(b.quantite_apres) ||
          !required(b.motif)) {
        return send(res, 400, { error: "Tous les champs obligatoires doivent être remplis." });
      }
      const avant = Number(b.quantite_avant);
      const apres = Number(b.quantite_apres);
      if (!Number.isFinite(avant) || !Number.isFinite(apres) || avant < 0 || apres < 0) {
        return send(res, 400, { error: "Quantités invalides." });
      }
      const rows = await sql`
        INSERT INTO ajustements_stock
          (produit_id, depot_id, quantite_avant, quantite_apres,
           motif, observations, utilisateur_id)
        VALUES
          (${b.produit_id}, ${b.depot_id}, ${avant}, ${apres},
           ${b.motif}, ${b.observations || null}, ${user.id})
        RETURNING *
      `;
      return send(res, 201, rows[0]);
    }

    return send(res, 404, { error: "Route API introuvable." });

  } catch (error) {
    console.error("GESTOCKD API:", error);
    if (error.code === "23505") {
      return send(res, 409, { error: "Cette valeur existe déjà." });
    }
    if (error.code === "23503") {
      return send(res, 409, { error: "Impossible de supprimer cet élément : il est utilisé dans l'historique." });
    }
    if (error.code === "23514") {
      return send(res, 400, { error: "Données invalides." });
    }
    return send(res, 500, { error: error.message || "Erreur interne du serveur." });
  }
}
