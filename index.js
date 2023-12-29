// Import required modules
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

// Create an Express application
const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/auth_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('Failed to connect to MongoDB:', err));

// Create a User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

// Create a User model
const User = mongoose.model('User', userSchema);

// Register route
app.post('/register', async (req, res) => {
  try {
    // Extract username and password from request body
    const { username, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' }); 
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    // Extract username and password from request body
    const { username, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Compare the password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate JWT
    const token = jwt.sign({ username: user.username }, 'this-is-my-sercret-1234', { expiresIn: '7d' });

    res.json({ token });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Protected route
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Protected route accessed successfully' });
});

// Middleware to verify JWT
function verifyToken(req, res, next) {
  let token = req.headers['authorization'];
  token = token.replace("Bearer ","");

  if (!token) {
    return res.status(403).json({ message: 'Token not provided' });
  }

  jwt.verify(token, 'this-is-my-sercret-1234', (err, decoded) => {
    if (err) {
        console.log(err)
      return res.status(401).json({ message: 'Invalid token' });
    }

    req.user = decoded.username;
    next();
  });
}

// Start the server
app.listen(3000, () => {
  console.log('Server started on port 3000');
});
