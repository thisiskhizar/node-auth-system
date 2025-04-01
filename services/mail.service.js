const nodemailer = require("nodemailer");
require("dotenv").config();

const {
  VERIFICATION_EMAIL_TEMPLATE,
  PASSWORD_RESET_SUCCESS_TEMPLATE,
  PASSWORD_RESET_REQUEST_TEMPLATE,
  WELCOME_EMAIL_TEMPLATE,
} = require("../constants/email.templates");

const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendVerificationEmail = async (email, token, code) => {
  try {
    const verificationLink = `${process.env.FRONTEND_URL}/verify/${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER, // Sender email
      to: email,
      subject: "Verify Your Email - Auth System",
      html: VERIFICATION_EMAIL_TEMPLATE.replace("{verificationCode}", code),
    };

    await transporter.sendMail(mailOptions);
    console.log(`Verification email sent to ${email}`);
  } catch (error) {
    console.error("Error sending verification email:", error);
    throw { status: 500, message: "Failed to send verification email." };
  }
};

const sendPasswordResetEmail = async (email, resetToken) => {
  try {
    const resetLink = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Reset Your Password - Auth System",
      html: PASSWORD_RESET_REQUEST_TEMPLATE.replace("{resetURL}", resetLink),
    };

    await transporter.sendMail(mailOptions);
    console.log(`Password reset email sent to ${email}`);
  } catch (error) {
    console.error("Error sending password reset email:", error);
    throw { status: 500, message: "Failed to send password reset email." };
  }
};

const sendResetSuccessEmail = async (email) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset Successful - Making Big",
      html: PASSWORD_RESET_SUCCESS_TEMPLATE,
    };

    await transporter.sendMail(mailOptions);
    console.log(`Password reset success email sent to ${email}`);
  } catch (error) {
    console.error("Error sending password reset success email:", error);
    throw {
      status: 500,
      message: "Failed to send password reset success email.",
    };
  }
};

const sendWelcomeEmail = async (email, name) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Welcome to Making Big",
      html: WELCOME_EMAIL_TEMPLATE.replace("{name}", name),
    };

    await transporter.sendMail(mailOptions);
    console.log(`Welcome email sent to ${email}`);
  } catch (error) {
    console.error("Error sending welcome email:", error);
    throw { status: 500, message: "Failed to send welcome email." };
  }
};

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendResetSuccessEmail,
  sendWelcomeEmail,
};
