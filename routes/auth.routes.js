const express = require("express");
const {
  registerUser,
  verifyEmailWithToken,
  verifyEmailWithCode,
  loginUser,
  refreshAccessToken,
  logoutUser,
  checkAuth,
  forgotPassword,
  resetPassword,
} = require("../controllers/auth.controller");
const verifyAccessToken = require("../middleware/auth.middleware");

const router = express.Router();

router.post("/register", registerUser);
router.get("/verify/:token", verifyEmailWithToken);
router.post("/verify-code", verifyEmailWithCode);

router.post("/login", loginUser);
router.post("/refresh-token", refreshAccessToken);
router.post("/logout", logoutUser);

router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

router.get("/check-auth", verifyAccessToken, checkAuth);

module.exports = router;