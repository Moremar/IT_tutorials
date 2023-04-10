const express    = require('express');
const bodyParser = require('body-parser');

/**
 * started with :    npm install
 *                   npm start     (that runs "node server.js")
 *
 * Basic Node.js web server using the Express framework.
 * Like the 01_basic_http_server example, it returns an HTML form for GET /admin/add-product
 * It receives the POST request on submission and returns the entered value.
 * 
 * This web server uses Express middlewares to parse the request body and handle routes.
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

// register a middleware that returns a form for GET /admin/add-product
// when submitting, it generates a POST /admin/add-product
app.get('/admin/add-product', (req, res, next) => {
    const htmlResponse = 
        '<html>'
        + '  <head><title>Add product</title></head>'
        + '  <body>'
        + '    <form action="/admin/add-product" method="POST">'
        + '      <input type="text" name="mess"/>'
        + '      <button type="submit">Send</button>'
        + '    </form>'
        + '  </body>'
        + '</html>';
    res.send(htmlResponse);
});

// register a middleware to receive the POST request when the form is submitted
app.post('/admin/add-product', (req, res, next) => {
    // access the request body parsed by the body-parser middleware in the "body" field
    res.send({title: req.body.mess});
});

// register a middleware for request GET /
app.get('/', (req, res, next) => {
    res.send('<h1>Welcome to the site !</h1>'
           + '<a href="/admin/add-product">Add Product</a>');
});

// create the web server using the express config and listen on port 3000
app.listen(3000);
