// 3rd-party imports
const express = require("express");
const bodyParser = require("body-parser");
const multer = require('multer');
const path = require("path");
const fs = require("fs");

// load custom env variables into process.env
const dotenv = require('dotenv');
dotenv.config();

// database configuration (must come after the .env file is loaded)
const mongoose = require('./database');

// custom packages
const feedRoutes = require("./routes/feed");
const authRoutes = require("./routes/auth");

/**
 * REST API in Node.js using JSON format for input and output data format.
 * The REST API itself is started with :
 * 
 *     $>  npm start
 * 
 * This is a project to show how to write tests in a Node,js project.
 * It uses as a base the backend part of 12_rest_api sample project.
 * 
 * Tests use Mocha, Chai and Sinon, and are written in the test/ folder.
 */

// initialize the Express app
const app = express();

// serve statically the /images folder
if (!fs.existsSync('./images')) {
    console.log('INFO - Creating the upload images folder');
    fs.mkdirSync('./images', { recursive: true });
}
app.use("/images", express.static(path.join(__dirname, "images")));

// body parser middleware to parse JSON body
app.use(bodyParser.json());

// middleware to extract the file in the "image" body field if available
// useful for the post image upload POST requests
const uploadStorage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, 'images/'); },
    filename: (req, file, cb) => { cb(null, new Date().getTime().toString() + '-' + file.originalname); }
});
const uploadFilter = (req, file, cb) => {
    const validFormat = file.mimetype === 'image/png' || file.mimetype === 'image/jpg' || file.mimetype === 'image/jpeg';
    cb(null, validFormat);
};
app.use(multer({ storage: uploadStorage, fileFilter: uploadFilter }).single("image"));


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
app.use("/auth", authRoutes);

// error-handling middleware
app.use((err, req, res, next) => {
    console.log(err);
    const status = err.statusCode || 500; // our custom property
    const message = err.message; // built-in property of Error class
    res.status(status).json({ message: message });
});

// start the web server
mongoose.connect(() => {
    console.log('Starting the web server');
    const server = app.listen(8080);
});