const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// Konfigurasi koneksi PostgreSQL
const pool = new Pool({
  user: "postgres",   // ganti dengan user PostgreSQL kamu
  host: "localhost",
  database: "mywarung",
  password: "postgres",   // ganti password PostgreSQL kamu
  port: 5432,
});

// Endpoint GET semua produk
app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM products ORDER BY id ASC");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint tambah produk
app.post("/api/products", async (req, res) => {
  const { name, price, category, description } = req.body;
  try {
    const result = await pool.query(
      "INSERT INTO products (name, price, category, description) VALUES ($1, $2, $3, $4) RETURNING *",
      [name, price, category, description]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint hapus produk
app.delete("/api/products/:id", async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query("DELETE FROM products WHERE id = $1", [id]);
    res.json({ message: "Produk berhasil dihapus" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Jalankan server
app.listen(3000, () => {
  console.log("✅ Server running on http://localhost:3000");
});
