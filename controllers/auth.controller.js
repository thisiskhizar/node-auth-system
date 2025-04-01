const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const User = require("../models/user.model");
const {
  registerValidation,
  verifyCodeValidation,
  loginValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
} = require("../middleware/validate");
const {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendResetSuccessEmail,
  sendWelcomeEmail,
} = require("../services/mail.service"); 
const _ = require("lodash");

const registerUser = async (req, res, next) => {
  try {
    // Validate Input
    const { error } = registerValidation(req.body);
    if (error) return next({ statusCode: 400, message: error.details[0].message });

    const { firstName, lastName, email, password, country } = req.body;

    // Check if user already exists
    let user = await User.findOne({ email });
    if (user && user.isVerified) return next({ statusCode: 400, message: "Email already in use" });

    if (user && !user.isVerified) {
      // If user exists but is not verified, resend verification email
      const verificationToken = crypto.randomBytes(32).toString("hex");
      const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

      user.verificationToken = verificationToken;
      user.verificationTokenExpiresAt = Date.now() + 30 * 60 * 1000; // 30 minutes
      user.verificationCode = verificationCode;
      user.verificationCodeExpiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

      await user.save();
      await sendVerificationEmail(email, verificationToken, verificationCode);

      return res.status(200).json({
        success: true,
        message: "This email is already registered but not verified. A new verification email has been sent.",
      });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generate verification token & code
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();

    const tokenExpireTime = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    const codeExpireTime = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create new user
    user = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      country,
      verificationToken,
      verificationTokenExpiresAt: tokenExpireTime,
      verificationCode,
      verificationCodeExpiresAt: codeExpireTime,
    });

    // Save user
    await user.save();

    // Send verification email
    await sendVerificationEmail(email, verificationToken, verificationCode);

    // Respond with a safe user object
    res.status(201).json({
      success: true,
      message: "User registered successfully. Verification email sent.",
      user: _.pick(user, [
        "_id",
        "firstName",
        "lastName",
        "email",
        "isVerified",
        "createdAt",
      ]),
    });
  } catch (error) {
    next(error);
  }
};

const verifyEmailWithToken = async (req, res, next) => {
  try {
    const { token } = req.params;

    // Find user by token
    const user = await User.findOne({
      verificationToken: token,
      verificationTokenExpiresAt: { $gt: Date.now() }, // Check if token is not expired
    });

    if (!user) return next({ statusCode: 400, message: "Invalid or expired verification token" });
    if (user.isVerified) return next({ statusCode: 400, message: "User is already verified" });

    // Mark user as verified
    user.isVerified = true;
    user.verificationToken = null;
    user.verificationTokenExpiresAt = null;
    user.verificationCode = null;
    user.verificationCodeExpiresAt = null;
    await user.save();

    await sendWelcomeEmail(user.email, user.firstName);

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    next(error);
  }
};

const verifyEmailWithCode = async (req, res, next) => {
  try {
    // Validate input
    const { error } = verifyCodeValidation(req.body);
    if (error) return next({ statusCode: 400, message: error.details[0].message });

    const { email, code } = req.body;

    // Find user by email and verification code
    const user = await User.findOne({
      email,
      verificationCode: code,
      verificationCodeExpiresAt: { $gt: Date.now() }, // Check if code is not expired
    });

    if (!user) return next({ statusCode: 400, message: "Invalid or expired verification code" });
    if (user.isVerified) return next({ statusCode: 400, message: "User is already verified" });

    // Mark user as verified
    user.isVerified = true;
    user.verificationToken = null;
    user.verificationTokenExpiresAt = null;
    user.verificationCode = null;
    user.verificationCodeExpiresAt = null;
    await user.save();

    await sendWelcomeEmail(user.email, user.firstName);

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (error) {
    next(error);
  }
};

const loginUser = async (req, res, next) => {
  try {
    // Validate input
    const { error } = loginValidation(req.body);
    if (error) return next({ statusCode: 400, message: error.details[0].message });

    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) return next({ statusCode: 400, message: "Invalid email or password" });

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return next({ statusCode: 400, message: "Invalid email or password" });

    // Ensure user is verified
    if (!user.isVerified) return next({ statusCode: 403, message: "Please verify your email first" });

    // Generate Tokens
    const accessToken = jwt.sign(
      { id: user._id, email: user.email },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "1d" } // Short-lived token (1 day)
    );

    const refreshToken = jwt.sign(
      { id: user._id },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" } // Long-lived token (7 days)
    );

    // Store refresh token in the database (optional but recommended)
    user.refreshToken = refreshToken;
    user.lastLogin = Date.now();
    await user.save();

    // Send refresh token as HTTP-Only Cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, // Prevents XSS attacks
      secure: process.env.NODE_ENV === "production", // Only send over HTTPS
      sameSite: "Strict", // Prevent CSRF attacks
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    // Send response
    res.status(200).json({
      success: true,
      message: "Login successful",
      accessToken,
      user: _.pick(user, [
        "_id",
        "firstName",
        "lastName",
        "email",
        "isVerified",
      ]),
    });
  } catch (error) {
    next(error);
  }
};

const refreshAccessToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return res.status(401).json({ success: false, message: "Unauthorized" });

    // Verify refresh token
    jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      async (err, decoded) => {
        if (err)
          return res
            .status(403)
            .json({ success: false, message: "Invalid refresh token" });

        // Find user
        const user = await User.findById(decoded.id);
        if (!user || user.refreshToken !== refreshToken) {
          return res
            .status(403)
            .json({ success: false, message: "Invalid refresh token" });
        }

        // Generate new access token
        const newAccessToken = jwt.sign(
          { id: user._id, email: user.email },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: "1d" }
        );

        res.status(200).json({ success: true, accessToken: newAccessToken });
      }
    );
  } catch (error) {
    next(error);
  }
};

const logoutUser = async (req, res, next) => {
  try {
    const { refreshToken } = req.cookies;
    if (!refreshToken) return res.status(400).json({ success: false, message: "Not logged in" });

    // Find user and remove refresh token
    const user = await User.findOneAndUpdate(
      { refreshToken },
      { refreshToken: null }
    );
    
    if (!user) return res.status(400).json({ success: false, message: "Invalid token" });

    // Clear cookie
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "Strict",
    });

    res.status(200).json({ success: true, message: "Logged out successfully" });
  } catch (error) {
    next(error);
  }
};

const checkAuth = async (req, res) => {
  try {
    res.status(200).json({
      success: true,
      user: req.user,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Something went wrong" });
  }
};

const forgotPassword = async (req, res, next) => {
  try {
    // Validate input
    const { error } = forgotPasswordValidation(req.body);
    if (error) return next({ statusCode: 400, message: error.details[0].message });

    const { email } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) return next({ statusCode: 400, message: "User not found" });

    // Generate a password reset token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiresAt = Date.now() + 30 * 60 * 1000; // 30 minutes expiry

    // Save reset token in the user document
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpiresAt = resetTokenExpiresAt;
    await user.save();

    // Send reset email
    await sendPasswordResetEmail(user.email, resetToken);

    res.status(200).json({
      success: true,
      message: "Password reset link has been sent to your email.",
    });
  } catch (error) {
    next(error);
  }
};

const resetPassword = async (req, res, next) => {
  try {
    // Validate input
    const { error } = resetPasswordValidation(req.body);
    if (error) return next({ statusCode: 400, message: error.details[0].message });

    const { token } = req.params;
    const { password } = req.body;

    // Find user with valid token
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpiresAt: { $gt: Date.now() }, // Token must not be expired
    });

    if (!user) return next({ statusCode: 400, message: "Invalid or expired token" });

    // Hash the new password
    const saltRounds = 10;
    user.password = await bcrypt.hash(password, saltRounds);

    // Clear reset token fields
    user.resetPasswordToken = null;
    user.resetPasswordExpiresAt = null;
    await user.save();

    // Send password reset success email
    await sendResetSuccessEmail(user.email);

    res.status(200).json({
      success: true,
      message: "Password reset successfully. You can now log in.",
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  registerUser,
  verifyEmailWithToken,
  verifyEmailWithCode,
  loginUser,
  refreshAccessToken,
  logoutUser,
  checkAuth,
  forgotPassword,
  resetPassword,
};
