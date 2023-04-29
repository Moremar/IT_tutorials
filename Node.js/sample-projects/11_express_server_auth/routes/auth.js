const express = require('express');

const authController = require('../controllers/auth');
const isAuth = require("../middlewares/is-auth");


const router = express.Router();

// GET /login
router.get('/login', authController.getLogin);

// POST /login
router.post('/login', authController.postLogin);

// GET /signup
router.get('/signup', authController.getSignup);

// POST /signup
router.post('/signup', authController.postSignup);

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