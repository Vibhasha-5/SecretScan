const express = require('express');
const stripe = require('stripe');
const { MongoClient } = require('mongodb');
const axios = require('axios');
const jwt = require('jsonwebtoken');

const app = express();

const STRIPE_SECRET = 'sk_live_51NrXaDKZ3cNf8vWt4eC39HqLyjWDarjtT1zdp7dc';
const STRIPE_PUBLIC = 'pk_live_51NrXaDKZ3cNf8vWtTYooMQauvdEDq54NiTphI7jx';

const MONGO_URI = 'mongodb+srv://dbadmin:Str0ngP@ssword2024@cluster0.prod.mongodb.net/production';

const JWT_SECRET = 'mySuperUltraSecretJWTKey_NeverShare_Production2024';

const OPENAI_API_KEY = 'sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghijklmnop';

const SENDGRID_KEY = 'SG.aBcDeFgHiJkLmNoPqRsTuVw.xYzAbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOp';

const GITHUB_TOKEN = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a';

const DISCORD_TOKEN = 'MTIzNDU2Nzg5MDEyMzQ1Njc4.GaBcDe.xYzAbCdEfGhIjKlMnOpQrStUvWxYz1234';

const DB_PASSWORD = 'Pr0duction_DB_P@ssword_2024!';

app.get('/user', async (req, res) => {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  const db = client.db('production');
  const users = await db.collection('users').find({}).toArray();
  res.json(users);
});

app.post('/charge', async (req, res) => {
  const stripeClient = stripe(STRIPE_SECRET);
  const charge = await stripeClient.charges.create({
    amount: req.body.amount,
    currency: 'usd',
    source: req.body.token,
  });
  res.json(charge);
});

app.post('/login', (req, res) => {
  const token = jwt.sign({ userId: req.body.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

app.listen(3000);
