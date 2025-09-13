const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const { MongoClient, ServerApiVersion } = require('mongodb');

const app = express();
app.use(bodyParser.json());

const uri = "mongodb+srv://xTheMo:JustForFun@121314@vulnctf.y7if0h1.mongodb.net/vulnctf?retryWrites=true&w=majority&appName=vulnCTF";
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

let usersCollection = null;
let inMemoryUsers = [
  { username: 'alice', password: 'alicegffdfjjjuyfdccpw', role: 'user' },
  { username: 'bob', password: 'bobprddcccxxxw', role: 'user' },
  { username: 'admin', password: 'admighuuhfxxiiutfddssnpw', role: 'admin' }
];

async function connectDb() {
  try {
    await client.connect();
    console.log('MongoDB connected');
    const db = client.db('VulnCTF');
    usersCollection = db.collection('users');

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

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey_for_ctf';

app.post('/login', async (req, res) => {
  try {
    const query = req.body;
    let user = null;
    if (usersCollection) {
      user = await usersCollection.findOne(query);
    } else {
      user = inMemoryUsers.find(u => {
        for (const k of Object.keys(query)) {
          if (u[k] !== query[k]) return false;
        }
        return true;
      });
    }
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ token });
  } catch (err) {
    console.error('[LOGIN] Error', err);
    return res.status(500).json({ error: 'server error' });
  }
});

function insecureAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Missing Authorization header' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ message: 'Invalid Authorization header format' });
  const token = parts[1].trim();
  try {
    const decoded = jwt.decode(token);
    if (!decoded) return res.status(401).json({ message: 'Invalid token' });
    req.user = decoded;
    next();
  } catch (err) {
    console.error('[AUTH] decode error', err);
    return res.status(401).json({ message: 'Invalid token' });
  }
}

app.get('/dashboard', insecureAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Insufficient privileges' });
  return res.json({ message: `Welcome admin ${req.user.username}!`, flag: 'CTF{example_flag_admin_access}' });
});

app.get('/', (req, res) => res.send('Vulnerable Node CTF app running.'));

const PORT = process.env.PORT || 3000;
connectDb().then(() => {
  app.listen(PORT, () => console.log(`Vulnerable Node CTF app listening on http://localhost:${PORT}`));
});
