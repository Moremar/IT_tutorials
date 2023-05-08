// 3rd-party imports
const express    = require("express");
const bodyParser = require("body-parser");

// custom packages
const feedRoutes = require("./routes/feed");

/**
 * REST API in Node.js using JSON format for input and output data format
 * 
 *     $>  npm start
 * 
 */

// initialize the Express app
const app = express();

// body parser middleware to parse JSON body
app.use(bodyParser.json());

// middleware logging incoming requests
app.use((req, res, next) => {
    console.log(req.method + " " + req.url);
    next();
});

// middleware to add CORS headers
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    next();
});

// register the routes
app.use("/feed", feedRoutes);


app.listen(8080);