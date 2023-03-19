const express    = require('express');
const bodyParser = require('body-parser');

// import the custom routes
const adminRoutes = require('./routes/admin');
const shopRoutes  = require('./routes/shop');

/**
 * started with :    npm install
 *                   npm start     (that runs "node server.js")
 *
 * Similar to 02_basic_express_server, but move the routes to a dedicated folder
 * and use the express Router object.
 * Also add a default 404 response for unhandled incoming requests.
 */

// create the web server config object
const app = express();

// register a middleware to parse the body of every incoming request
app.use(bodyParser.urlencoded({ extended: true }));

// register a middleware for all requests to log the method, URL and body
app.use((req, res, next) => {
    console.log(req.method + " " + req.url);
    console.log(req.body);
    next();
});

// register the routes middlewares
app.use('/admin', adminRoutes);      // with a route prefix
app.use(shopRoutes);                 // without a route prefix

// return a 404 for unsupported requests, for ex GET /xxx
app.use((req, res, next) => {
    res.status(404).send('<h1>Page not found</h1>');
});

// create the web server using the express config and listen on port 3000
app.listen(3000);
