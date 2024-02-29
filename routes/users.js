const mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();


const Connection = async () => {
  const URL = process.env.DB_CONNECTION_STRING;

  try {
    await mongoose.connect(URL);
    console.log('Database connected successfully');
  } catch (error) {
    console.error('Error connecting to the database', error);
  }
};

Connection();


const userSchema = mongoose.Schema({
  username: {
    type: String,
    unique: true,
    required: true,
    trim: true, // Automatically trims whitespace from both ends
    validate: {
      validator: function (value) {
        // Check if the username contains any whitespace
        return !/\s/.test(value);
      },
      message: 'Username must not contain spaces'
    }
  },
  password: String,
  contact: {
    type: String,
    unique: true,
    validate: {
      validator: function (v) {
        return /^([0-9]{10}$)/.test(v);
      }
    },
    required: true
  },
  role: {
    type: String,
    default: 'user'
  },
});

// bcryptjs

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }
  try {
    const hashedPassword = await bcrypt.hash(this.password, 10);
    this.password = hashedPassword;
    next();
  } catch (error) {
    console.error('Error hashing the password', error);
  }
});

// jsonwebtoken
userSchema.methods.generateToken = async function () {
  try {
    return jwt.sign({ _id: this._id }, process.env.JWT_SECRET_KEY, { expiresIn: "30d" });
  } catch (error) {
    console.error('Error generating token', error);
  }
};

// Method to compare passwords
userSchema.methods.comparePassword = async function (password) {
  try {
    return bcrypt.compare(password, this.password);
  } catch (error) {
    throw error;
  }
};


module.exports = mongoose.model("user", userSchema);