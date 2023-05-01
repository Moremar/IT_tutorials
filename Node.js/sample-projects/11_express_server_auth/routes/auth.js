const express = require('express');
const { check, body } = require('express-validator');


const authController = require('../controllers/auth');
const isAuth = require("../middlewares/is-auth");
const user = require('../models/user');


const router = express.Router();

// GET /login
router.get('/login', authController.getLogin);

// POST /login
router.post('/login',
    check('email')
        .isEmail()
        .withMessage('The email is invalid.')
        .normalizeEmail(),
    body('password', 'Password must be alphanumeric and at least 6 characters long')
        .trim()
        .isLength({min: 6})
        .isAlphanumeric(),
    authController.postLogin);

// GET /signup
router.get('/signup', authController.getSignup);

// POST /signup
router.post('/signup', 
    // field validation, if a field is not valid, a error is added to the query, that
    // can be accessed by the next middleware via validationResult(req)
    check('email')
        .isEmail()
        .withMessage('The email is invalid.')   // error message only for the isEmail() validation
        .normalizeEmail()
        .custom((value, {req}) => { 
            // synchronous custom validation
            if (value === 'test@test.com') {
                throw new Error('Forbidden email address.');
            }
            return true;
        })
        .custom((value, { req }) => {
            // asynchronous custom validation
            return user.findOne({ email: value })
              .then((user) => {
                if (user) {
                    // email already in use
                    return Promise.reject('An account already exists for this email.');
                }
              });
        }),
    body('password', 'Password must be alphanumeric and at least 6 characters long')  // error for all password validations
        .trim()
        .isLength({min: 6})
        .isAlphanumeric(),
    body('confirmPassword')
        .trim()
        .custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Passwords do not match');
            }
            return true;
        })
        .isLength({min: 6})
        .isAlphanumeric(),
    authController.postSignup);

// POST /logout
router.post('/logout', isAuth, authController.postLogout);

// GET /reset-password-link
// show the page to request a password change link
router.get('/reset-password-link', authController.getResetPasswordLink);

// POST /reset-password-link
// send an email with a link to reset the password
router.post('/reset-password-link', authController.postResetPasswordLink);

// GET /reset-password/:token
// show the page to reset the password
router.get('/reset-password/:token', authController.getResetPassword);

// POST /reset-password/
// reset the password for the user with a given reset token
router.post('/reset-password', authController.postResetPassword);


module.exports = router;