const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

// name, email, photo, password, passWordConfirm

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'A user must provide a name']
  },
  email: {
    type: String,
    required: [true, 'A user must have a email'],
    unique: true,
    trim: true,
    maxlength: [
      40,
      'A tour name must have less then or equal to 40 characters'
    ],
    minlength: [1, 'A tour name must have more then or equal to 10 characters'],
    validate: [validator.isEmail, 'A user must provide a valid email']
  },
  photo: String,
  password: {
    type: String,
    required: [true, 'A user must provide a password'],
    minLength: 8
  },
  passwordConfirm: {
    type: String,
    required: [true, 'A user must confirm their password'],
    validate: {
      // This validation only works on CREATE and SAVE
      validator: function(el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!'
    }
  }
});

userSchema.pre('save', async function(next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirmed field
  this.passwordConfirm = undefined;

  next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;
