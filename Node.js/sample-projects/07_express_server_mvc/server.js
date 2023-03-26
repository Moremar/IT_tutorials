const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');

const notFoundController = require('./controllers/error');

// import the custom routes
const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');

/**
 * started with :    npm install
 *                   npm start     (that runs "node server.js")
 *
 * Similar to 06_express_server_with_ejs_templates, but separates the code according to the MVC pattern.
 * Instead of having all the logic in the routes files :
 *  - the routes only list what endpoints are supported and call the controller
 *  - the controller perform required actions, and instanciate objects from the model
 *  - the models define the objects used in the app, and how they get saved
 *    in this app we save to a file, it could also be saved to a DB
 */


// create the web server config object
const app = express();

// setup express to use EJS templating engine
app.set('view engine', 'ejs');
app.set('views', 'views');

// expose public folder
app.use(express.static(path.join(__dirname, 'public')));

// register a middleware to parse the body of every incoming request
app.use(bodyParser.urlencoded({ extended: true }));

// register the routes middlewares
app.use('/admin', adminRoutes);      // with a route prefix
app.use(shopRoutes);                 // without a route prefix

// return a 404 for unsupported requests
app.use(notFoundController.getNotFoundPage);

// create the web server using the express config and listen on port 3000
app.listen(3000);
