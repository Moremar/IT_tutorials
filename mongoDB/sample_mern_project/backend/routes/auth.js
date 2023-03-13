const Router = require('express').Router;
const jwt    = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db     = require('../db');

const router = Router();

const createToken = () => {
  return jwt.sign({}, 'secret', { expiresIn: '1h' });
};

router.post('/login', (req, res, next) => {
  const email = req.body.email;
  const pw = req.body.password;

  db.getClient()
    .db("shop")
    .collection("users")
    .findOne({email: email})
    .then(
      (user) => {
        // compare returns a promise, so returning it allows to get its result in the next then()
        return bcrypt.compare(pw, user.password);
      }
    )
    .then(
      (pwdMatches) => {
        if (!pwdMatches) {
          console.log("Password does not match.");
          res.status(401).json({ message: "No user with the email/password." });
        } else {
          // valid user
          const token = createToken();
          res.status(200).json({ token: token, user: { email: email } });
        }
      }
    )
    .catch(
      (err) => {
        console.log(err);
        res.status(401).json({ message: "No user with the email/password." });
      }
    );
});

router.post('/signup', (req, res, next) => {
  const email = req.body.email;
  const pw = req.body.password;

  // Hash password before storing it in database => Encryption at Rest
  bcrypt
    .hash(pw, 12)
    .then(hashedPW => {
      // add the shop user to the MongoDB "users" database
      db.getClient()
        .db("shop")
        .collection("users")
        .insertOne({email: email, password: hashedPW})
        .then(
          (mongoDbRes) => {
            console.log(mongoDbRes);
            const token = createToken();
            res.status(201).json({ token: token, user: { email: email } });
          }
        )
        .catch(
          (err) => {
            console.log(err);
            res.status(500).json({ message: "Failed to save the new user in the database."});
          }
        );      
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({ message: 'Creating the user failed.' });
    });
});

module.exports = router;
