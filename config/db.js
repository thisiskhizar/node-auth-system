const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("MongoDB Connected...");
  } catch (error) {
    console.error("Database connection failed:", error);
    throw error; // Ensure the server does not start if DB fails
  }
};

module.exports = connectDB;