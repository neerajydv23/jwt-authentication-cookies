var express = require('express');
var router = express.Router();
const userModel = require('./users')
require('dotenv').config();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


/* GET home page. */
router.get('/', function (req, res, next) {
  res.render('index', { title: 'Express' });
});
router.get('/register', function (req, res, next) {
  res.render('register');
});
router.get('/login', function (req, res, next) {
  res.render('login');
});
router.get('/forgot', function (req, res, next) {
  res.render('forgot');
});

router.get('/profile', isLoggedIn, function (req, res, next) {
  res.render('profile');
});
router.get('/adminAccess', isAdmin, function (req, res, next) {
  res.render('adminAccess');
});

router.post('/register', async function (req, res, next) {
  try {

    const { username, password, contact } = req.body;

    const existingUser = await userModel.findOne({ contact });
    if (existingUser) {
      return res.status(400).json({ error: 'Contact already exists' });
    }

    const userCreated = await userModel.create({ username, contact, password })

    const token = await userCreated.generateToken();
    res.cookie('token', token, { httpOnly: true }); // Set token as a cookie
    res.redirect('/profile'); // Redirect to profile page
  }

  catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while registering the user' });
  };
});

router.post('/login', async function (req, res, next) {
  try {
    const { username, password } = req.body;
    const userExist = await userModel.findOne({ username });
    if (!userExist) {
      return res.status(400).json({ error: 'invalid credentials ' });
    }

    const user = await userExist.comparePassword(password);

    if (user) {
      const token = await userExist.generateToken();
      res.cookie('token', token, { httpOnly: true }); // Set token as a cookie
      res.redirect('/profile'); // Redirect to profile page
    } else {
      return res.status(400).json({ error: 'invalid credentials ' });
    }

  }
  catch (error) {
    console.error(error);
    res.status(500).json({ error: 'An error occurred while login' });
  };
});

router.get('/logout', (req, res) => {
  res.clearCookie('token'); // Clear the token cookie
  res.redirect('/'); // Redirect to login page
});

router.post('/forgot', async function (req, res, next) {
  const { contact } = req.body;

  try {
    const user = await userModel.findOne({ contact });

    if (user) {
      const token =  await user.generateToken();

      res.cookie('token', token, { httpOnly: true });
      return res.redirect('/profile');
    } else {
      return res.redirect('/forgot');
    }
  } catch (err) {
    console.error('Error:', err);
    return res.redirect('/forgot');
  }
});


function isLoggedIn(req, res, next) {
  const token = req.cookies.token;

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET_KEY, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).send('Token expired');
      }
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

async function isAdmin(req, res, next) {
  const token = req.cookies.token;

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET_KEY, async (err, user) => {
    if (err) return res.sendStatus(403);
    const userRole = await userModel.findById(user._id);
    if (userRole.role != 'admin') {
      res.status(400).json({ success: false, message: "only admin is allowed" });
    } else {
      req.user = user;
      next();
    }
  });
}

module.exports = router;
