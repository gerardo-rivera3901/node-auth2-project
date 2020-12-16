const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = require('express').Router();
const { jwtSecret } = require('../config/secret');

const Users = require('./api-model');
const mw = require('./middleware/middleware');

router.post('/register', mw.isValid, async (req, res) => {
  try {
    const user = req.body;
    const rounds = process.env.BCRYPT_ROUNDS || 8;
    const hash = bcrypt.hashSync(user.password, rounds);
    user.password = hash;
    const data = await Users.addUser(user);
    res.status(201).json(data);
  } catch(err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/login', mw.isValid, async (req, res) => {
  try {
    const user = req.body;
    const foundUser = await Users.findBy({ username: user.username });
    if(foundUser && bcrypt.compareSync(user.password, foundUser.password)) {
      const token = makeToken(foundUser);
      res.status(200).json({ message: `Welcome back ${foundUser.username}`, token });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch(err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/users', async (req, res) => {
  try {
    const data = await Users.getAll();
    res.status(200).json(data);
  } catch(err) {
    res.status(500).json({ message: err.message });
  }
});

const makeToken = (user) => {
  const payload = {
    subject: user.id,
    username: user.username,
    role: user.role
  };
  const options = {
    expiresIn: '60s'
  };
  return jwt.sign(payload, jwtSecret, options);
};

module.exports = router;
