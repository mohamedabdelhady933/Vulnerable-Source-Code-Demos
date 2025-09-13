// server.js
// Deliberately vulnerable Node.js + Express app.
// 1) Login route uses the raw request body as the MongoDB query -> NoSQL injection possible.
// 2) JWT auth middleware decodes JWT WITHOUT verifying signature -> attacker can remove/alter signature and change role.

const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const app = express();
app.use(bodyParser.json());

// Change if you run MongoDB on a different URI. If not available, the server will fallback to an in-memory array.
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017';
const DB_NAME = 'vuln_ctf_db';

let usersCollection = null;
let inMemoryUsers = [
  { username: 'alice', password: 'alicepw', role: 'user' },
  { username: 'bob', password: 'bobpw', role: 'user' },
  { username: 'admin', password: 'adminpw', role: 'admin' }
];

async function connectDb() {
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    const db = client.db(DB_NAME);
    usersCollection = db.collection('users');

    // seed minimal users if collection empty
    const count = await usersCollection.countDocuments();
    if (count === 0) {
      await usersCollection.insertMany(inMemoryUsers);
      console.log('[DB] Seeded users into MongoDB collection `users`.');
    } else {
      console.log('[DB] Found existing user documents.');
    }
  } catch (err) {
    console.warn('[DB] Could not connect to MongoDB, falling back to in-memory users. Error:', err.message);
    usersCollection = null;
  }
}

// NOTE: This secret is intentionally present but JWT verification is later bypassed.
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey_for_ctf';

// ---------- Vulnerable login route (NoSQL injection) ----------
// IMPORTANT: this intentionally uses the raw request body as the MongoDB query.
// If you send JSON operators (e.g. $or, $ne, etc.) in the body, MongoDB will treat them as operators.
app.post('/login', async (req, res) => {
  try {
    const query = req.body; // <-- intentionally vulnerable: using raw body as query

    let user = null;
    if (usersCollection) {
      // If you're using MongoDB, this will accept operator objects from the client
      user = await usersCollection.findOne(query);
    } else {
      // naive fallback that simulates a MongoDB "findOne(query)" behavior for simple keys only
      user = inMemoryUsers.find(u => {
        for (const k of Object.keys(query)) {
          // NOTE: this fallback does NOT implement operators and is only for when MongoDB is not available.
          if (u[k] !== query[k]) return false;
        }
        return true;
      });
    }

    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    // create JWT normally
    const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ token });
  } catch (err) {
    console.error('[LOGIN] Error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

// ---------- Vulnerable JWT auth middleware (improper validation) ----------
// This middleware DECODES the token and trusts the payload WITHOUT verifying the signature.
// That means a token with a modified payload (or with no signature) can be accepted.
function insecureAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Missing Authorization header' });

  // Expect: Bearer <token>
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ message: 'Invalid Authorization header format' });

  const token = parts[1].trim();

  // WARNING: jwt.decode does NOT validate signatures. This is intentionally insecure for the CTF.
  try {
    const decoded = jwt.decode(token); // <-- intentionally insecure
    if (!decoded) return res.status(401).json({ message: 'Invalid token' });

    // attach decoded payload to request
    req.user = decoded;
    next();
  } catch (err) {
    console.error('[AUTH] decode error', err);
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// Protected route: dashboard
app.get('/dashboard', insecureAuth, (req, res) => {
  // simple role-based access control
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Insufficient privileges' });
  }

  // return a sensitive flag for the CTF
  return res.json({ message: `Welcome admin ${req.user.username}!`, flag: 'CTF{example_flag_admin_access}' });
});

// health
app.get('/', (req, res) => res.send('Vulnerable Node CTF app running.'));

// start server
const PORT = process.env.PORT || 3000;
connectDb().then(() => {
  app.listen(PORT, () => console.log(`Vulnerable Node CTF app listening on http://localhost:${PORT}`));
});
