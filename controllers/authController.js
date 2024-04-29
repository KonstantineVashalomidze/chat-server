// Required modules
const jwt = require("jsonwebtoken"); // For generating JSON Web Tokens
const otpGenerator = require("otp-generator"); // For generating OTPs
const mailService = require("../services/mailer"); // For sending emails
const crypto = require("crypto"); // For cryptographic operations
const { promisify } = require("util"); // For converting callback-based functions to promise-based
const catchAsync = require("../utils/catchAsync"); // For handling asynchronous errors

// Utility functions and custom modules
const sanitizeObject = require("../utils/sanitizeObject"); // For sanitizing objects
const User = require("../models/user"); // User model
const otp = require("../Templates/Mail/otp"); // Template for OTP email
const resetPassword = require("../Templates/Mail/resetPassword"); // Template for reset password email
require('dotenv').config(); // Load ENV

// Function to generate a JWT (JSON Web Token) for a given user ID
const generateJWT = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);

// Middleware function to handle user signup
exports.signup = catchAsync(async (req, res, next) => {
  // Extract relevant fields from request body
  const { firstName, lastName, email, password } = req.body;

  // Sanitize the request body to include only specific fields
  const sanitizedObject = sanitizeObject(
    req.body,
    "firstName",
    "lastName",
    "email",
    "password"
  );


  // Check if a user with the given email already exists in the database
  const user = await User.findOne({ email: email });

  if (user && user.verified) {
    // If a verified user with this email exists, return an error response
    return res.status(400).json({
      status: "error",
      message: "This email is already in use, Log In instead.",
    });
  } else if (user) {
    // If a user with this email exists but is not verified, update their information
    await User.findOneAndUpdate(
        { email: email }, // Filter for finding the user to update
        sanitizedObject, // Data to update with
        {new: true, validateModifiedOnly: true,} // Options: return the updated document, and validate only modified paths
    );

    // Generate an OTP (One-Time Password) and send it to the user's email
    req.userId = user._id; // Set the user ID in the request object
    next(); // Move to the next middleware function
  } else {
    // If a user with this email does not exist, create a new user

    // Create a new user with the sanitized data
    const newUser = await User.create(sanitizedObject);

    // Generate an OTP and send it to the user's email
    req.userId = newUser._id;
    next();
  }
});

// Middleware function to send OTP (One-Time Password) to the user's email
exports.sendOTP = catchAsync(async (req, res, next) => {
  const { userId } = req; // Extract user ID from request
  // Generate a new OTP (6 digits) without special characters
  const newOtp = otpGenerator.generate(6, {
    upperCaseAlphabets: false,
    specialChars: false,
    lowerCaseAlphabets: false,
  });

  // Calculate OTP expiry time (5 minutes after OTP is sent)
  const otpExpirationTime = Date.now() + 5 * 60 * 1000;

  // Find the user by ID and update OTP expiry time
  const user = await User.findByIdAndUpdate(userId, {
    otpExpirationTime: otpExpirationTime,
  });

  user.otp = newOtp.toString(); // Update the user's OTP

  await user.save({ new: true, validateModifiedOnly: true });  // Save the updated user

  // Send an email containing the OTP to the user
  mailService.sendEmail({
    from: process.env.SENDER_EMAIL,
    to: user.email,
    subject: "Verification OTP",
    html: otp(user.firstName, newOtp), // HTML content for the email body
    attachments: [] // No attachments
  });

  // Respond with success status and message
  res.status(200).json({
    status: "success",
    message: "OTP was sent to the " + user.email
  });
});

// Middleware function to verify OTP (One-Time Password) and update user accordingly
exports.verifyOTP = catchAsync(async (req, res, next) => {
  const { email, otp } = req.body; // Extract email and OTP from request body

  // Find user with the provided email and valid OTP
  const user = await User.findOne({
    email,
    otpExpirationTime: { $gt: Date.now() }, // Check if OTP is still valid
  });

  // If no user found or OTP expired, return error
  if (!user) {
    return res.status(400).json({
      status: "error",
      message: "Email is doesn't exist or OTP expired",
    });
  }

  // If user is already verified, return error
  if (user.verified) {
    return res.status(400).json({
      status: "error",
      message: "Email is already verified",
    });
  }

  // If OTP is incorrect, return error
  if (!(await user.correctOTP(otp, user.otp))) {
    res.status(400).json({
      status: "error",
      message: "OTP is incorrect",
    });
    return;
  }

  /* OTP is correct */

  // Mark user as verified, clear OTP, and save changes
  user.verified = true;
  user.otp = undefined;
  await user.save({ new: true, validateModifiedOnly: true });

  const token = generateJWT(user._id); // Generate JWT (JSON Web Token) for the user

  // Respond with success status, token, and user ID
  res.status(200).json({
    status: "success",
    message: "OTP verified Successfully!",
    token,
    userId: user._id,
  });
});

// Middleware function to handle user login
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body; // Extract email and password from request body

  if (!email || !password) {   // Check if both email and password are provided
    res.status(400).json({
      status: "error",
      message: "Both email and password are required",
    });
    return;
  }

  // Find user by email in the database including password field
  const user = await User.findOne({ email: email }).select("+password");

  if (!user || !user.password) { // If no user found or no password is set for the user, return error
    res.status(400).json({
      status: "error",
      message: "User was not found with such email or password is not set for this user",
    });
    return;
  }

  // Check if the provided password matches the user's password in the database or user is found with provided email
  if (!user || !(await user.comparePasswords(password, user.password))) {
    res.status(400).json({
      status: "error",
      message: "Email or password is incorrect",
    });

    return;
  }

  const token = generateJWT(user._id); // Generate JWT (JSON Web Token) for the user

  // Respond with success status, token, and user ID
  res.status(200).json({
    status: "success",
    message: "Logged in successfully!",
    token,
    userId: user._id,
  });
});

// This middleware function is responsible for protecting routes by verifying the user's JSON Web Token (JWT)
exports.protect = catchAsync(async (req, res, next) => {
  // It first attempts to extract the JWT from the Authorization header or the jwt cookie
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    // If the Authorization header is present and starts with "Bearer ", it means the JWT is sent using the
    // Bearer scheme.
    // The actual token is extracted by splitting the header value and taking the second part (after the space)
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    // If the Authorization header is not present, the middleware checks for the JWT in the cookies
    // This allows for stateless authentication using either headers or cookies
    token = req.cookies.jwt;
  }

  if (!token) {
    // If no token is found, it means the user is not authenticated
    // In this case, a 401 Unauthorized response is sent with a message asking the user to log in
    return res.status(401).json({
      message: "Log in first to get access.",
    });
  }
  // If a token is found, it is verified using the JWT_SECRET environment variable
  // The promisify function is likely used to convert the callback-based jwt.verify function to a Promise
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // After verifying the token, the middleware checks if the user associated with the token
  // still exists in the database
  // This is important in case the user was deleted after the token was issued
  const associatedWithTokenUser = await User.findById(decoded.userId);
  if (!associatedWithTokenUser) {
    // If the user doesn't exist, it means the token is invalid (e.g., the user was deleted)
    // In this case, a 401 Unauthorized response is sent with a message indicating the user no longer exists
    return res.status(401).json({
      message: "User with that token doesn't exist anymore.",
    });
  }
  // Even if the user exists, the middleware checks if the user changed their password after the token was issued
  // If the password was changed, the token is considered invalid and cannot be used for authentication
  if (associatedWithTokenUser.changedPasswordAfter(decoded.iat)) {
    // If the user changed their password, a 401 Unauthorized response is sent with a
    // message asking the user to log in again
    return res.status(401).json({
      message: "Password was changed, please Log in again.",
    });
  }


  // If all checks pass, it means the user is authenticated and the token is valid
  // The user object is attached to the request object for use in subsequent middleware functions or route handlers
  req.user = associatedWithTokenUser;
  next();
});

exports.forgotPassword = catchAsync(async (req, res, next) => {
  /* Find user based on provided email */
  const user = await User.findOne({ email: req.body.email });

  if (!user) { // If user not found, return error response
    return res.status(404).json({
      status: "error",
      message: "There is no user with such an email.",
    });
  }

  /* Generate a random password reset token */
  const resetToken = user.generatePasswordResetToken();
  await user.save({ validateBeforeSave: false }); // Save the user with the new reset token (without validation)

  /* Send the reset token to the user's email */
  try {
    // Construct the reset URL using the reset token
    const resetURL = `http://localhost:3001/auth/new-password?token=${resetToken}`;

    // Email the user with the reset URL
    mailService.sendEmail({
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Reset Password",
      html: resetPassword(user.firstName, resetURL),
      attachments: []
    });

    // Respond with success status
    res.status(200).json({
      status: "success",
      message: "Token sent to email!",
    });

  } catch (err) {
    // If there's an error sending the email, handle it
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    // Return error response
    return res.status(500).json({
      message: "There was an error sending the email. Try again later!",
    });
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  /* Hash the token provided in the request body to match with stored hashed token */
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.body.token)
    .digest("hex");

  // Find user by hashed password reset token and check if token has not expired
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() } // Check if token is not expired
  });

// If token is invalid or expired, return error response
  if (!user) {
    return res.status(400).json({
      status: "error",
      message: "Token is Invalid or Expired",
    });
  }

  /*  If token is valid and not expired, set the new password and clear reset token and expiration */
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save(); // Save the updated user

  /* Generate JWT (JSON Web Token) for the user */
  const token = generateJWT(user._id);

  // Respond with success status and JWT
  res.status(200).json({
    status: "success",
    message: "Password updated Successfully",
    token,
  });
});