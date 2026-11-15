// SYNTHETIC FIXTURE - deliberately vulnerable code, for the whitebox demo only.
// It exists so `code_ingest` has something real to read: routes, one concatenated
// query, one parameterised query that must NOT produce a lead, and one route that
// mutates data without an auth check.
const express = require('express');
const db = require('./db');
const { requireAuth } = require('./auth');

const app = express();
app.use(express.json());

// Concatenated: the lead the demo is about.
app.get('/sql', async (req, res) => {
  const q = req.query.q;
  const rows = await db.query("SELECT id, name FROM items WHERE name = '" + q + "'");
  res.send(rows);
});

// Parameterised: same input shape, no lead should be produced.
app.get('/safe', requireAuth, async (req, res) => {
  const q = req.query.q;
  const rows = await db.query('SELECT id, name FROM items WHERE name = ?', [q]);
  res.send(rows);
});

// Mutating, no auth middleware in this file.
app.post('/admin/items', async (req, res) => {
  await db.query('INSERT INTO items (name) VALUES (?)', [req.body.name]);
  res.send({ ok: true });
});

app.get('/search', (req, res) => {
  res.send('<p>results for ' + req.query.q + '</p>');
});

module.exports = app;
