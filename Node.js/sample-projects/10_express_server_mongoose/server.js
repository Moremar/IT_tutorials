const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');

// load custom env variables into process.env
const dotenv = require('dotenv');
dotenv.config();

// database configuration (must come after the .env file is loaded)
const mongoose = require('./database');
//const User = require('./models/user');

// import the custom routes
const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const notFoundController = require('./controllers/error');
const User = require('./models/user');

/**
 * started with :    npm install
 *                   vim .env      (create the .env file with DB config as detailed in database.js)
 *                   npm start     (that runs "node server.js")
 *
 * Builds on 09_express_server_mongodb, but uses the Mongoose ODM module instead of raw MongoDB library.
 */


// create the web server config object
const app = express();

// setup express to use EJS templating engine
app.set('view engine', 'ejs');
app.set('views', 'views');

// expose public folder
app.use(express.static(path.join(__dirname, 'public')));

// middleware to parse the body of every incoming request
app.use(bodyParser.urlencoded({ extended: true }));

// middleware to enrich the request with the user Model instance
// for now, it just attaches to the request the user with email xxxxx created at startup (no real user management yet)
app.use((req, res, next) => {
  User.findOne({ email: 'xxxxx' })
    .then((user) => {
      req.user = user;
      next();
    }).catch((err) => {
      console.log('ERROR - Could not retrieve user');
      console.log(err);
    });
});

// middleware to log every incoming request
app.use((req, res, next) => {
    console.log(req.method + ' ' + req.url);
    next();
});

// register the routes middlewares
app.use('/admin', adminRoutes);      // with a route prefix
app.use(shopRoutes);                 // without a route prefix

// return a 404 for unsupported requests
app.use(notFoundController.getNotFoundPage);


mongoose.connect(() => {
  // create the "userdev" user if it does not exist yet
  // this is just a quick hack to get a user instance without proper user management
  // in a real app, there would be a user created in DB for each user signing up
  User.find({ email: 'xxxxx' })
  .then((users) => {
    if (users.length === 0) {
      console.log('Creating system user "userdev" in the database');
      const systemUser = new User({ name: 'userdev', email: 'xxxxx', cart: [] });
      return systemUser.save();
    }
    return Promise.resolve();
  })
  .then(() => {
    console.log('Starting the web server');
    app.listen(3000);
  })
  .catch((err) => {
    console.log('ERROR - Failed to create "userdev" user.');
    console.log(err);
  });
});
