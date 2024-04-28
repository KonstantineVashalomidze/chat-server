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
    from: process.env.OTP_SENDER_EMAIL,
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

exports.verifyOTP = catchAsync(async (req, res, next) => {
  // verify otp and update user accordingly
  const { email, otp } = req.body;
  const user = await User.findOne({
    email,
    otpExpirationTime: { $gt: Date.now() },
  });

  if (!user) {
    return res.status(400).json({
      status: "error",
      message: "Email is invalid or OTP expired",
    });
  }

  if (user.verified) {
    return res.status(400).json({
      status: "error",
      message: "Email is already verified",
    });
  }

  if (!(await user.correctOTP(otp, user.otp))) {
    res.status(400).json({
      status: "error",
      message: "OTP is incorrect",
    });

    return;
  }

  // OTP is correct

  user.verified = true;
  user.otp = undefined;
  await user.save({ new: true, validateModifiedOnly: true });

  const token = generateJWT(user._id);

  res.status(200).json({
    status: "success",
    message: "OTP verified Successfully!",
    token,
    user_id: user._id,
  });
});

// User Login
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // console.log(email, password);

  if (!email || !password) {
    res.status(400).json({
      status: "error",
      message: "Both email and password are required",
    });
    return;
  }

  const user = await User.findOne({ email: email }).select("+password");

  if (!user || !user.password) {
    res.status(400).json({
      status: "error",
      message: "Incorrect password",
    });

    return;
  }

  if (!user || !(await user.correctPassword(password, user.password))) {
    res.status(400).json({
      status: "error",
      message: "Email or password is incorrect",
    });

    return;
  }

  const token = generateJWT(user._id);

  res.status(200).json({
    status: "success",
    message: "Logged in successfully!",
    token,
    user_id: user._id,
  });
});

// Protect
exports.protect = catchAsync(async (req, res, next) => {
  // 1) Getting token and check if it's there
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  if (!token) {
    return res.status(401).json({
      message: "You are not logged in! Please log in to get access.",
    });
  }
  // 2) Verification of token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  console.log(decoded);

  // 3) Check if user still exists

  const this_user = await User.findById(decoded.userId);
  if (!this_user) {
    return res.status(401).json({
      message: "The user belonging to this token does no longer exists.",
    });
  }
  // 4) Check if user changed password after the token was issued
  if (this_user.changedPasswordAfter(decoded.iat)) {
    return res.status(401).json({
      message: "User recently changed password! Please log in again.",
    });
  }

  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = this_user;
  next();
});

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(404).json({
      status: "error",
      message: "There is no user with email address.",
    });
  }

  // 2) Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send it to user's email
  try {
    const resetURL = `http://localhost:3000/auth/new-password?token=${resetToken}`;
    // TODO => Send Email with this Reset URL to user's email address

    console.log(resetURL);

    mailService.sendEmail({
      from: "shreyanshshah242@gmail.com",
      to: user.email,
      subject: "Reset Password",
      html: resetPassword(user.firstName, resetURL),
      attachments: [],
    });

    res.status(200).json({
      status: "success",
      message: "Token sent to email!",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return res.status(500).json({
      message: "There was an error sending the email. Try again later!",
    });
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on the token
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.body.token)
    .digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  // 2) If token has not expired, and there is user, set the new password
  if (!user) {
    return res.status(400).json({
      status: "error",
      message: "Token is Invalid or Expired",
    });
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // 3) Update changedPasswordAt property for the user
  // 4) Log the user in, send JWT
  const token = generateJWT(user._id);

  res.status(200).json({
    status: "success",
    message: "Password Reseted Successfully",
    token,
  });
});
