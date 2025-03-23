const express = require("express");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const errorHandler = require("./middleware/errorHandler");
const authRoutes = require("./routes/auth.routes");

// Load environment variables
dotenv.config();

// Initialize Express
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // Enable cookie parsing

// Enable CORS with credentials (so cookies can be sent from frontend)
app.use(
  cors({
    origin: process.env.CLIENT_URL, // Allow specific origin
    credentials: true,
  })
);

// Security
app.use(helmet()); // Set security headers
app.use(morgan("dev")); // HTTP request logger

// Routes
app.use("/api/v1/auth", authRoutes);

// Test Route
app.get("/", (req, res) => {
  res.send("API is running...");
});

// Error Handling Middleware
app.use(errorHandler);

// Connect to Database first, then start the server
connectDB()
  .then(() => {
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error("Server failed to start:", err);
    process.exit(1); // Exit process if DB fails to connect
  });
