const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  plan: {
    type: String,
    enum: ["BASIC", "STANDARD", "PREMIUM"],
    default: "BASIC"
  }
}, { timestamps: true });

module.exports = mongoose.model("User", userSchema);
