const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const port = 5000;
const SECRET_KEY = 'your_secret_key';

app.use(cors());
app.use(express.json());

// ✅ Updated MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/userAuth')
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'customer' },
});

const User = mongoose.model('User', userSchema);

// Register Endpoint
app.post('/register', async (req, res) => {
  const { username, email, password, role } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = new User({ username, email, password: hashedPassword, role });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});

// Login Endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } catch (err) {
    res.status(500).json({ message: 'Internal server error', error: err.message });
  }
});

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
});

// Update User Details Endpoint
app.put('/update-user', async (req, res) => {
  const { email, newUsername, newEmail, newPassword, newRole } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required to identify user' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Update fields if provided
    if (newUsername) user.username = newUsername;
    if (newEmail) user.email = newEmail;
    if (newPassword) user.password = bcrypt.hashSync(newPassword, 10);
    if (newRole) user.role = newRole;

    await user.save();
    res.status(200).json({ message: 'User details updated successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error updating user details', error: error.message });
  }
});
