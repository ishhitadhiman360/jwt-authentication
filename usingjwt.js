const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const User = require('./database');

const app = express();

// JWT secret key
const JWT_SECRET = 'your-secret-key';

// Setup session middleware
app.use(session({
  secret: 'your-secret-key', // Secret used to sign the session ID cookie
  resave: false, // Don't save session if unmodified
  saveUninitialized: false, // Don't create a session until something is stored
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(__dirname + '/public'));

// const limiter = rateLimit({
//   windowMs: 5 * 60 * 1000,
//   max: 5,
//   message: 'Too many requests, please try again later.'
// });
// app.use('/login', limiter);

app.use(morgan('dev'));

// Middleware to verify JWT
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.token;
  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.redirect('/login');
      }
      req.user = user;
      next();
    });
  } else {
    res.redirect('/login');
  }
};

// Handle requests to the root URL
app.get('/', (req, res) => {
  const user = req.session.user;
  if (!user) {
    res.redirect('/login');
  } else {
    res.redirect('/home');
  }
});

// Handle requests to the login page
app.get('/login', (req, res) => {
  const user = req.session.user;
  if (user) {
    res.redirect('/home');
  } else {
    res.sendFile(__dirname + '/public/index.html');
  }
});

// Handle POST requests to the login page
app.post('/login', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username }).lean();
    if (user && bcrypt.compareSync(req.body.password, user.password)) {
      // Save the user's username in the session
      req.session.user = req.body.username;

      // Generate JWT token with a unique ID (jti)
      const tokenId = uuidv4();
      const token = jwt.sign({ username: user.username, jti: tokenId }, JWT_SECRET, { expiresIn: '1h' });

      // Log the JWT token ID
      console.log('Generated JWT Token ID:', tokenId);

      // Update login time and increment login count
      await User.updateOne({ username: req.body.username }, { 
        $set: { loginTime: new Date() }, 
        $inc: { loginCount: 1 } 
      });

      // Set cookies to indicate the user is logged in and store the JWT
      res.cookie('login', 'Yes', { secure: true, httpOnly: true });
      res.cookie('token', token, { secure: true, httpOnly: true });

      res.redirect('/home');
    } else {
      res.sendFile(__dirname + '/public/index.html');
    }
  } catch (error) {
    console.error(error);
    res.redirect('/login');
  }
});

// Handle POST requests to log out the user
app.post('/logout', async (req, res) => {
  // Update logout time
  await User.updateOne({ username: req.session.user }, { $set: { logoutTime: new Date() } });

  // Destroy the session and remove the login cookie and JWT
  req.session.destroy();
  res.cookie('login', 'No', { secure: true, httpOnly: true });
  res.cookie('token', '', { secure: true, httpOnly: true, expires: new Date(0) });
  res.redirect('/login');
});

// Route for the home page ('/home')
app.get('/home', authenticateJWT, async (req, res) => {
  const users = await User.find().lean();
  if (!users) {
    res.redirect('/login');
  } else {
    const userRows = users.map(user => `
      <tr>
        <td>${user.username}</td>
        <td>${user.password}</td>
        <td>${user.loginTime ? new Date(user.loginTime).toLocaleString() : 'N/A'}</td>
        <td>${user.logoutTime ? new Date(user.logoutTime).toLocaleString() : 'N/A'}</td>
        <td>${user.loginCount}</td>
      </tr>
    `).join('');

    res.send(`
      <!DOCTYPE html>
      <html>
        <head>
          <title>Home</title>
          <link rel="stylesheet" href="style.css">
          <style>
            body {
              font-family: Arial, sans-serif;
            }
            .navbar {
              overflow: hidden;
              background-color: #333;
              display: flex;
              align-items: center;
            }
            .navbar a, .navbar button {
              display: block;
              color: #f2f2f2;
              text-align: center;
              padding: 14px 16px;
              text-decoration: none;
              background: none;
              border: none;
              cursor: pointer;
            }
            .navbar a:hover, .navbar button:hover {
              background-color: #ddd;
              color: black;
            }
            .logo {
              height: 50px;
              margin: 5px 20px;
            }
            .logout-btn {
              border: 1px solid white;
              margin-left: auto;
            }
            .logout-btn:hover {
              background-color: grey;
            }
            table {
              width: 100%;
              border-collapse: collapse;
              margin-top: 20px;
            }
            th, td {
              padding: 8px 12px;
              border: 1px solid #ddd;
              text-align: left;
            }
            th {
              background-color: #f2f2f2;
            }
          </style>
        </head>
        <body>
          <div class="navbar">
            <a href="/home">Home</a>
            <form action="/logout" method="POST" style="margin: 0;">
              <button type="submit" class="logout-btn">Log out</button>
            </form>
          </div>
          <h1>Welcome!</h1>
          <p>You are now logged in.</p>
          <table>
            <tr>
              <th>Username</th>
              <th>Password</th>
              <th>Login Time</th>
              <th>Logout Time</th>
              <th>Login Count</th>
            </tr>
            ${userRows}
          </table>
        </body>
      </html>
    `);
  }
});

 

// Route for the signup page ('/signup')
app.get('/signup', (req, res) => {
  res.sendFile(__dirname + '/public/signup.html');
});

app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username }).lean();
    if (existingUser) {
      res.sendFile(__dirname + '/public/signup.html');
    } else {
      const hashedPassword = bcrypt.hashSync(password, 10);
      await User.create({ username, password: hashedPassword });
      res.redirect('/login');
    }
  } catch (error) {
    res.status(500).send('Error signing up');
  }
});

// Setup server to listen on port 3000
const port = 3000;
app.listen(port, () => console.log(`Listening on port ${port}`));
