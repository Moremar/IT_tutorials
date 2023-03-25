const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');

// import the custom routes
const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');

/**
 * started with :    npm install
 *                   npm start     (that runs "node server.js")
 *
 * Similar to 05_express_server_with_pug_templates, but uses EJS templates 
 * instead of Pug templates for HTML responses
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
app.use((req, res, next) => {
    // use an EJS template
    res.render('not-found', {pageTitle: 'Not Found'});
});

// create the web server using the express config and listen on port 3000
app.listen(3000);
