const Joi = require("joi");

const strongPasswordRegex = new RegExp(
  "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+])[A-Za-z\\d!@#$%^&*()_+]{8,}$"
);

const registerValidation = (data) => {
  const schema = Joi.object({
    firstName: Joi.string().min(2).max(50).trim().required().messages({
      "string.min": "First name must be at least 2 characters long.",
      "string.max": "First name cannot exceed 50 characters.",
      "any.required": "First name is required.",
    }),
    lastName: Joi.string().min(2).max(50).trim().required().messages({
      "string.min": "Last name must be at least 2 characters long.",
      "string.max": "Last name cannot exceed 50 characters.",
      "any.required": "Last name is required.",
    }),
    email: Joi.string().email().trim().required().messages({
      "string.email": "Invalid email format.",
      "any.required": "Email is required.",
    }),
    password: Joi.string().pattern(strongPasswordRegex).required().messages({
      "string.pattern.base":
        "Password must be at least 8 characters, include 1 uppercase, 1 lowercase, 1 number, and 1 special character.",
      "any.required": "Password is required.",
    }),
  });

  return schema.validate(data);
};

const verifyCodeValidation = (data) => {
  const schema = Joi.object({
    email: Joi.string().email().required().messages({
      "string.email": "Invalid email format",
      "any.required": "Email is required",
    }),
    code: Joi.string()
      .length(6)
      .pattern(/^[0-9]+$/)
      .required()
      .messages({
        "string.length": "Verification code must be exactly 6 digits",
        "string.pattern.base": "Verification code must contain only numbers",
        "any.required": "Verification code is required",
      }),
  });

  return schema.validate(data);
};

const loginValidation = (data) => {
  const schema = Joi.object({
    email: Joi.string().email().required().messages({
      "string.email": "Invalid email format",
      "any.required": "Email is required",
    }),
    password: Joi.string().min(8).required().messages({
      "string.min": "Password must be at least 8 characters",
      "any.required": "Password is required",
    }),
  });

  return schema.validate(data);
};

const forgotPasswordValidation = (data) => {
  const schema = Joi.object({
    email: Joi.string().email().trim().required().messages({
      "string.email": "Invalid email format.",
      "any.required": "Email is required.",
    }),
  });

  return schema.validate(data);
};

const resetPasswordValidation = (data) => {
  const schema = Joi.object({
    password: Joi.string()
      .min(8)
      .pattern(strongPasswordRegex)
      .required()
      .messages({
        "string.min": "New password must be at least 8 characters long.",
        "string.pattern.base":
          "New password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character.",
        "any.required": "New password is required.",
      }),
  });

  return schema.validate(data);
};

module.exports = {
  registerValidation,
  verifyCodeValidation,
  loginValidation,
  forgotPasswordValidation,
  resetPasswordValidation,
};
