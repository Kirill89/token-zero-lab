// Token Zero lab -- INTENTIONALLY VULNERABLE. Never expose it to a network.
//
// A secret arrives in a JSON body, nobody checks that it is a string, the driver
// sends a JS number to MySQL/MariaDB as a number, and the database then compares
// the stored string column as a number: 'abc' = 0 is true, '7b2e' = 7 is true.

const express = require('express');
const mysql = require('mysql2/promise');

const app = express();
app.use(express.json()); // keeps JSON types: {"token": 0} is the NUMBER 0, not "0"

const db = mysql.createPool({ host: 'db', user: 'lab', password: 'lab', database: 'lab' });

// Fake users: email, password, reset_token, api_key.
// As numbers the secrets are: alice 0, bob 7, carol 4821 / 305, dave 12e2 = 1200 / 3e1 = 30.
const USERS = [
  ['alice@lab.test', 'alice-password', 'kq8ZrmWxTnPa', 'zk5f3a9cd17b'],
  ['bob@lab.test',   'bob-password',   '7b2e9fd0c1a4', '7fa93c0de215'],
  ['carol@lab.test', 'carol-password', '4821fa09bc77', '305c1d88e0ab'],
  ['dave@lab.test',  'dave-password',  '12e2xk40cd9f', '3e1x9k27ab6c'],
];

// VULNERABLE. The query is parameterised, so this is not SQL injection: the value
// just has the wrong type. {"token": 0} runs as  reset_token = 0
// FIX: if (typeof email !== 'string' || typeof token !== 'string') return res.status(400).end();
app.post('/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;
  const [rows] = await db.query(
    'SELECT id, email FROM users WHERE email = ? AND reset_token = ?', [email, token]);
  if (rows.length === 0) return res.status(401).json({ error: 'Invalid email or token' });
  await db.query('UPDATE users SET password = ?, reset_token = NULL WHERE id = ?',
    [String(newPassword), rows[0].id]);
  res.json({ message: `Password changed for ${rows[0].email}` });
});

// VULNERABLE in the same way.
// FIX: if (typeof apiKey !== 'string') return res.status(400).end();
app.post('/whoami', async (req, res) => {
  const { apiKey } = req.body;
  const [rows] = await db.query('SELECT id, email FROM users WHERE api_key = ?', [apiKey]);
  if (rows.length === 0) return res.status(401).json({ error: 'Invalid API key' });
  res.json({ message: `You are ${rows[0].email}` });
});

// Ordinary login, to check a password before and after a reset. It has the
// string check, so it is not affected by the bug.
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (typeof email !== 'string' || typeof password !== 'string') return res.status(400).end();
  const [rows] = await db.query('SELECT id FROM users WHERE email = ? AND password = ?', [email, password]);
  if (rows.length === 0) return res.status(401).json({ error: 'Wrong email or password' });
  res.json({ message: `Logged in as ${email}` });
});

// Recreate the table with the fake users on every start, then listen.
async function main() {
  await db.query('DROP TABLE IF EXISTS users');
  await db.query(`CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100), password VARCHAR(100), reset_token VARCHAR(64), api_key VARCHAR(64))`);
  await db.query('INSERT INTO users (email, password, reset_token, api_key) VALUES ?', [USERS]);
  app.listen(3000, () => console.log('Token Zero lab on port 3000'));
}
main();
