const express  = require("express");
const { body } = require("express-validator");

const authController = require("../controllers/auth.js");
const User = require("../models/user");

const router = express.Router();


// POST /auth/signup
// create a user account
router.post("/signup", 
  // validation of fields in the request body
  // in case of error, the error is accessible from the validationRsult field in the controller
  [
    body("email")
      .trim()
      .isEmail()
      .normalizeEmail()
      .withMessage("Please enter a valid email")
      .custom((value, { req }) => {
        return User.findOne({ email : value })
        .then((user) => {
            if (user) {
                Promise.reject("Email address already in use");
            }
        });
      }),
    body("password")
      .trim()
      .isLength({ min: 5 }),
    body("name")
      .trim()
      .isLength({ min: 3 })
  ],
  authController.signup);


// POST /auth/login
// login a user to his account and return a JWT token
router.post("/login", authController.login);

module.exports = router;