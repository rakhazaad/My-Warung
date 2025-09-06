// backend/index.js
import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { Pool } from "pg";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "mywarung_secret";

// __dirname for ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "../frontend")));

// Simple request logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Postgres pool — sesuaikan kredensialmu
const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "mywarung",
  password: "genius2299",
  port: 5432,
});

// Helper: run query
async function query(sql, params = []) {
  const client = await pool.connect();
  try {
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

// AUTH helpers
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Token required" });
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return res.status(401).json({ message: "Invalid authorization format" });
  const token = parts[1];
  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    console.error("TOKEN VERIFY ERROR:", err);
    return res.status(403).json({ message: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") return res.status(403).json({ message: "Anda tidak memiliki akses" });
  next();
}

// ================= ROUTES ==================

// --- REGISTER ---
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const uname = (username || "").trim();
    const _role = (role || "user").trim();

    if (!uname || !password) return res.status(400).json({ message: "Lengkapi data (username & password)" });

    const exist = await query("SELECT 1 FROM users WHERE username=$1", [uname]);
    if (exist.rowCount > 0) return res.status(409).json({ message: "User sudah terdaftar" });

    const hashed = await bcrypt.hash(password, 10);
    await query("INSERT INTO users (username, password, role) VALUES ($1,$2,$3)", [uname, hashed, _role]);

    return res.json({ message: "Registrasi berhasil" });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res.status(500).json({ message: "Gagal register" });
  }
});

// --- LOGIN ---
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const uname = (username || "").trim();
    if (!uname || !password) return res.status(400).json({ message: "Username dan password wajib diisi" });

    const result = await query("SELECT * FROM users WHERE username=$1", [uname]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ message: "User tidak ditemukan" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Password salah" });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "8h" });
    return res.json({ token, role: user.role });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({ message: "Gagal login" });
  }
});

// --- GET MY INFO ---
app.get("/api/me", authMiddleware, (req, res) => {
  return res.json({ user: req.user });
});

// --- ADMIN STATS ---
app.get("/api/admin/stats", authMiddleware, adminOnly, async (_req, res) => {
  try {
    // Try to compute today stats using created_at if column exists.
    // If queries fail (e.g. created_at missing), fallback to simple totals.
    try {
      const totalProductsQ = await query("SELECT COUNT(*)::int AS cnt FROM products");
      const totalUsersQ = await query("SELECT COUNT(*)::int AS cnt FROM users");
      // these two use created_at; may throw if column missing
      const totalOrdersTodayQ = await query("SELECT COUNT(*)::int AS cnt FROM orders WHERE DATE(created_at) = CURRENT_DATE");
      const totalRevenueTodayQ = await query("SELECT COALESCE(SUM(total),0)::numeric AS total FROM orders WHERE DATE(created_at) = CURRENT_DATE");

      return res.json({
        totalProducts: totalProductsQ.rows[0].cnt,
        totalUsers: totalUsersQ.rows[0].cnt,
        totalOrdersToday: totalOrdersTodayQ.rows[0].cnt,
        totalRevenueToday: Number(totalRevenueTodayQ.rows[0].total)
      });
    } catch (innerErr) {
      // fallback if created_at doesn't exist or query failed
      console.warn("ADMIN STATS: fallback due to:", innerErr.message || innerErr);
      const totalProductsQ = await query("SELECT COUNT(*)::int AS cnt FROM products");
      const totalUsersQ = await query("SELECT COUNT(*)::int AS cnt FROM users");
      const totalOrdersQ = await query("SELECT COUNT(*)::int AS cnt FROM orders");
      const totalRevenueQ = await query("SELECT COALESCE(SUM(total),0)::numeric AS total FROM orders");

      return res.json({
        totalProducts: totalProductsQ.rows[0].cnt,
        totalUsers: totalUsersQ.rows[0].cnt,
        totalOrdersToday: totalOrdersQ.rows[0].cnt,         // fallback uses total orders
        totalRevenueToday: Number(totalRevenueQ.rows[0].total)
      });
    }
  } catch (err) {
    console.error("ADMIN STATS ERROR:", err);
    return res.status(500).json({ message: "Gagal mengambil statistik" });
  }
});

// --- USERS (admin only) ---
app.get("/api/users", authMiddleware, adminOnly, async (_req, res) => {
  try {
    const result = await query("SELECT id, username, role FROM users ORDER BY id ASC");
    return res.json(result.rows);
  } catch (err) {
    console.error("GET USERS ERROR:", err);
    return res.status(500).json({ message: "Gagal mengambil data user" });
  }
});

app.post("/api/users", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const uname = (username || "").trim();
    if (!uname || !password) return res.status(400).json({ message: "Username & password wajib" });

    const exist = await query("SELECT 1 FROM users WHERE username=$1", [uname]);
    if (exist.rowCount > 0) return res.status(409).json({ message: "Username sudah digunakan" });

    const hashed = await bcrypt.hash(password, 10);
    await query("INSERT INTO users (username, password, role) VALUES ($1,$2,$3)", [uname, hashed, role || "user"]);
    return res.json({ message: "User berhasil ditambahkan" });
  } catch (err) {
    console.error("CREATE USER ERROR:", err);
    return res.status(500).json({ message: "Gagal menambahkan user" });
  }
});

app.delete("/api/users/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    await query("DELETE FROM users WHERE id=$1", [id]);
    return res.json({ message: "User dihapus" });
  } catch (err) {
    console.error("DELETE USER ERROR:", err);
    return res.status(500).json({ message: "Gagal menghapus user" });
  }
});

// --- PRODUCTS ---
app.get("/api/products", async (_req, res) => {
  try {
    const r = await query("SELECT id, name, price, category, description FROM products ORDER BY id ASC");
    return res.json(r.rows);
  } catch (err) {
    console.error("GET PRODUCTS ERROR:", err);
    return res.status(500).json({ message: "Gagal mengambil data produk" });
  }
});

app.post("/api/products", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { name, price, category, desc } = req.body;
    await query("INSERT INTO products (name, price, category, description) VALUES ($1,$2,$3,$4)", [name, price, category, desc]);
    return res.json({ message: "Produk ditambahkan" });
  } catch (err) {
    console.error("CREATE PRODUCT ERROR:", err);
    return res.status(500).json({ message: "Gagal menambahkan produk" });
  }
});

app.put("/api/products/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    const { name, price, category, desc } = req.body;
    await query("UPDATE products SET name=$1, price=$2, category=$3, description=$4 WHERE id=$5", [name, price, category, desc, req.params.id]);
    return res.json({ message: "Produk diupdate" });
  } catch (err) {
    console.error("UPDATE PRODUCT ERROR:", err);
    return res.status(500).json({ message: "Gagal mengupdate produk" });
  }
});

app.delete("/api/products/:id", authMiddleware, adminOnly, async (req, res) => {
  try {
    await query("DELETE FROM products WHERE id=$1", [req.params.id]);
    return res.json({ message: "Produk dihapus" });
  } catch (err) {
    console.error("DELETE PRODUCT ERROR:", err);
    return res.status(500).json({ message: "Gagal menghapus produk" });
  }
});

// --- ORDERS ---
app.post("/api/orders", async (req, res) => {
  try {
    const { items, subtotal, fee, total, paymentMethod } = req.body;
    // If orders table has created_at with default NOW(), this works fine.
    const r = await query(
      "INSERT INTO orders (items, subtotal, fee, total, payment_method, created_at) VALUES ($1,$2,$3,$4,$5,NOW()) RETURNING *",
      [JSON.stringify(items), subtotal, fee, total, paymentMethod]
    );
    return res.json(r.rows[0]);
  } catch (err) {
    console.error("CREATE ORDER ERROR:", err);
    return res.status(500).json({ message: "Gagal membuat order" });
  }
});

app.get("/api/orders", authMiddleware, adminOnly, async (_req, res) => {
  try {
    // Return orders with created_at (if present)
    const r = await query("SELECT id, items, subtotal, fee, total, payment_method, created_at FROM orders ORDER BY COALESCE(created_at, NOW()) DESC");
    return res.json(r.rows);
  } catch (err) {
    console.error("GET ORDERS ERROR:", err);
    return res.status(500).json({ message: "Gagal mengambil data order" });
  }
});

// Fallback for non-API routes -> serve frontend index
app.get(/^(?!\/api\/).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "../frontend/index.html"));
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server berjalan di http://localhost:${PORT}`);
});
