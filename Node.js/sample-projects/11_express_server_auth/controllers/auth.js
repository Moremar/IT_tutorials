const bcrypt     = require("bcryptjs");
const nodemailer = require('nodemailer');
const sendgrid   = require('nodemailer-sendgrid-transport');
const crypto     = require('crypto');
const { validationResult } = require('express-validator');


const User = require('../models/user');

/*
 * Controller for auth operations : signup / login / logout / reset password
 */


// configure nodemailer with the SendGrid 3rd party mail server
// for this to work, a SendGrid account must have been created, and the following
// information must be added to the .env file :
//   SENDGRID_API_KEY="xxx"        // the API key to access the Sengrid account
//   SENDGRID_FROM_EMAIL="xxx"     // the email used in the "from" field of the emails, must be a registered identity in the SendGrid account
const transporter = nodemailer.createTransport(sendgrid({
  auth: { api_key: process.env.SENDGRID_API_KEY }
}));


exports.getLogin = (req, res, next) => {
  // if an error was flashed, display it in the view
  let errorMessage = req.flash('error');
  errorMessage = errorMessage.length > 0 ? errorMessage[0] : '';
  res.render('login', {
    pageTitle: 'Login',
    errorMessage: errorMessage
  });
};


exports.postLogin = (req, res, next) => {
  console.log("Login");
  const email = req.body.email;
  const password = req.body.password;
  User.findOne({ email: email })
  .then((user) => {
    if (!user) {
      console.log("WARNING - No user with email " + email);
      req.flash('error', 'Invalid email or password.');
      return res.redirect('/login');
    }
    bcrypt.compare(password, user.password)
    .then((ok) => {
      if (!ok) {
        console.log("WARNING - Password does not match");
        req.flash('error', 'Invalid email or password.');
        return res.redirect('/login');
      }
      // password matches, login authorized        
      req.session.isAuthenticated = true;
      req.session.user = user;
      return req.session.save(() => {
        // we redirect once the session is saved, so the user will be
        // correctly authenticated
        return res.redirect('/');
      });
    })
  }).catch((err) => {
    console.log('ERROR - Server error during login');
    next(err);
  });
};


exports.getSignup = (req, res, next) => {
  // if an error was flashed, display it in the view
  let errorMessage = req.flash('error');
  errorMessage = errorMessage.length > 0 ? errorMessage[0] : '';
  res.render('signup', {
    pageTitle: 'Signup',
    errorMessage: errorMessage,
    oldInput: {email: '', password: '', confirmPassword: ''},
    validationErrors: []    // used for red borders on error fields in the view
  });
};


exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;

  // retrieve fields validation results from the check() middleware
  const validationErrors = validationResult(req);
  if (!validationErrors.isEmpty()) {
    // 422 : Validation failed status
    return res.status(422).render('signup', {
      pageTitle: 'Signup',
      errorMessage: validationErrors.array()[0].msg,
      // keep the previous user input so it does not get lost on reload
      oldInput: { email: email, password: password, confirmPassword: confirmPassword },
      validationErrors: validationErrors.array()    // used for red borders on error fields in the view
    });
  }

  // no need to check that the email address is not already used
  // this check was already done by the validation middleware
  return bcrypt.hash(password, 12)
  .then((hashedPassword) => {
    const newUser = new User({ email: email, password: hashedPassword, cart: {items: []} });
    return newUser.save();
  })
  .then(() => {
    console.log("Created new user " + email);
    res.redirect("/login");
  });
};


// on logout, we destroy the session, so the session ID cookie is deleted
exports.postLogout = (req, res, next) => {
  req.session.destroy(() => {
    console.log("Logout");
    res.redirect('/');
  });
};


// the first step to reset a password is to request a reset link to be sent to our email
// the will display to form to request this email
exports.getResetPasswordLink = (req, res, next) => {
  // if an error was flashed, display it in the view
  let errorMessage = req.flash('error');
  errorMessage = errorMessage.length > 0 ? errorMessage[0] : '';
  res.render('reset-password-link', { pageTitle: 'Reset Password Link', errorMessage: errorMessage });
};


// Send the password reset email to the address for which the password reset was requested
exports.postResetPasswordLink = (req, res, next) => {
  const email = req.body.email;
  // generate a 32-bytes unique temporary token
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      // should never happen
      console.log(err);
      return res.redirect("/reset-password-link");
    }
    const token = buffer.toString('hex');
    User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        console.log('WARNING - Requested password reset for address ' + email + ' that does not exist in the database');
        req.flash('error', 'No account for this email address.');
        return res.redirect('/reset-password-link');
      }
      user.resetToken = token;
      user.resetTokenExpiration = Date.now() + 10 * 60 * 1000;  // password reset token valid for 10 minutes

      // nested promise chain to not execute it if we redirected in case of invalid email
      user.save()
      .then(() => {
        // redirect before sending the link, no need to block the user during that time
        res.redirect('/login');
        // send the reset link with the unique token
        return transporter.sendMail({
          to: email,
          from: process.env.SENDGRID_FROM_EMAIL,
          subject: 'Password Reset Request',
          html: `
            <p>You requested a password reset.<p>
            <p>Click this <a href="http://localhost:3000/reset-password/${token}">link</a> to reset your password.</p>
          `
        });
      })
      .then(() => { 
        console.log('Reset password email sent to ' + email);
      })
    })
    .catch((err) => {
      console.log('ERROR - Could not send the password reset email.');
      next(err);
    });
  });
};


// when the user clicks the password reset link from the email, we check the token, and if it is valid
// we render a form to actually reset the password
exports.getResetPassword = (req, res, next) => {
  // get the user with the requested token
  const resetToken = req.params.token;
  User.findOne({ resetToken: resetToken, resetTokenExpiration: { $gt: Date.now() } })
  .then((user) => {
    if (!user) {
      console.log('WARNING - No user with reset token ' + resetToken);
      req.flash('error', 'Invalid password reset link');
      return res.redirect('/login');
    }
    // the user exists, we display the reset password page
    return res.render('reset-password', { pageTitle: 'Reset Password', resetToken: resetToken });
  })
  .catch((err) => {
    console.log('ERROR - Could not display the reset password page');
    next(err);
  });
};


// on submission of the new password, we check again the token validity.
// If valid, the password is updated and the temporary token is removed from the DB
exports.postResetPassword = (req, res, next) => {
  // get the user with the requested token
  const resetToken = req.body.resetToken;
  const password = req.body.password;
  User.findOne({ resetToken: resetToken, resetTokenExpiration: { $gt: Date.now() } })
  .then((user) => {
    // check if the user is valid
    if (!user) {
      console.log('WARNING - No user with reset token ' + resetToken);
      req.flash('error', 'Invalid password reset link');
      return res.redirect('/login');
    }
    // Note : if we want to add password policy check, we can do it here
    // update the password
    return bcrypt.hash(password, 12)
    // nested promise chain to not execute the then() when the user or token is invalid
    .then((hashedPassword) => {
      user.password = hashedPassword;
      user.resetToken = undefined;
      user.resetTokenExpiration = undefined;
      return user.save();
    })
    .then(() => {
      console.log('Password reset successfully for user ' + user.email);
      return res.redirect('/login');
    });
  })
  .catch((err) => {
    console.log('ERROR - Could not reset the password');
    next(err);
  });
};
