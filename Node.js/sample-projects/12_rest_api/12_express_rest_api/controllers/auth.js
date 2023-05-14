const { validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const User = require("../models/user");


exports.signup = (req, res, next) => {
    // handle potential validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const error = new Error("Validation failed");
        error.statusCode = 422;
        throw error;
    }
    const email    = req.body.email;
    const password = req.body.password;
    const name     = req.body.name;
    bcrypt.hash(password, 12)
    .then((hashedPassword) => {
        const user = new User({
            email: email,
            password: hashedPassword,
            name: name,
            status: "NEW"
        });
        return user.save();
    })
    .then((created) => {
        res.status(201).json({ message: "User " + email + " created.", userId: created._id });
    })
    .catch((err) => {
        next(err);
    });
};


exports.login = (req, res, next) => {
    const email    = req.body.email;
    const password = req.body.password;
    let currUser;
    User.findOne({ email : email })
    .then((user) => {
        if (!user) {
            // no account for the provided email
            const error = new Error("Invalid credentials");
            error.statusCode = 401;
            throw error;
        }
        currUser = user;
        return bcrypt.compare(password, user.password);
    })
    .then((match) => {
        if (!match) {
            // invalid password
            const error = new Error("Invalid credentials");
            error.statusCode = 401;
            throw error;
        }
        // generate a webtoken
        const token = jwt.sign({
            email: email,
            userId: currUser._id.toString(),
          }, 
          // secret key used on server-side to encrypt and decrypt JWT tokens
          process.env.JWT_KEY,
          // JWT token options
          { expiresIn: "1h" }
        );
        res.status(200).json({ token: token, userId: currUser._id });
    })
    .catch((err) => {
        next(err);
    });
};
