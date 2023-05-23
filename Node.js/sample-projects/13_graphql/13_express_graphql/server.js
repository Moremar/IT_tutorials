// 3rd-party imports
const express    = require("express");
const bodyParser = require("body-parser");
const multer     = require('multer');
const path       = require("path");
const helmet     = require("helmet");
const compression = require("compression");
const morgan     = require("morgan");
const fs         = require("fs");

const fileUtil = require("./utils/file");

// GraphQL middleware, schema and resolvers
const { graphqlHTTP }  = require("express-graphql");
const graphqlSchema    = require("./graphql/schema");
const graphqlResolvers = require("./graphql/resolvers");

// load custom env variables into process.env
const dotenv = require('dotenv');
dotenv.config();

// database configuration (must come after the .env file is loaded)
const mongoose = require('./database');

// middleware checking if the user is authenticated
const auth = require("./middlewares/auth");


/**
 * GraphQL API, all requests target the POST /graphql endpoint.
 * The body of the request specify what resolver to use, according to the schema.
 * 
 *     $>  npm start
 * 
 * The .env configuration file should look like :
 * 
 *   MONGODB_HOST="xxxxx"
 *   MONGODB_USER="xxxxx"
 *   MONGODB_PASSWORD="xxxxx"
 *   MONGODB_DATABASE="xxxxx"
 *   JWT_KEY="xxxxx"
 * 
 * The React frontend using this GraphQL API is started with the same command from the sibling folder ../13_react_frontend
 */

// initialize the Express app
const app = express();

// serve statically the /images folder
app.use("/images", express.static(path.join(__dirname, "images")));

// set some security HTTP headers to all HTTP responses
app.use(helmet());

// set up compression to reduce the response size
app.use(compression());

// specify a logger for all incoming HTTP requests
const logStream = fs.createWriteStream(
    path.join(__dirname, "access.log"),
    { flags: "a" }   // append mode
);
app.use(morgan('combined', { stream: logStream }));

// body parser middleware to parse JSON body
app.use(bodyParser.json());

// middleware to extract the file in the "image" body field if available
// useful for the post image upload POST requests
const uploadStorage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, 'images/'); },
    filename:    (req, file, cb) => { cb(null, new Date().getTime().toString() + '-' + file.originalname); }
});
const uploadFilter = (req, file, cb) => {
    const validFormat = file.mimetype === 'image/png' || file.mimetype === 'image/jpg' || file.mimetype === 'image/jpeg';
    cb(null, validFormat);
};
 app.use(multer({storage: uploadStorage, fileFilter: uploadFilter}).single("image"));


 // middleware to add CORS headers
app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    // hack for GraphQL : the GraphQL middleware declines every request that is neither GET not POST
    // the browser usually sends a OPTIONS request before sending a POST, and this OPTIONS requests receives
    // an error response
    // To avoid that, we just return an empty success response to OPTIONS requests
    if (req.method == "OPTIONS") {
        console.log("Return 200 status for OPTIONS");
        return res.sendStatus(200);
    }

    next();
});


// before calling the GraphQL endpoint, we call a middleware that will check if
// the user is currently authenticated of not
app.use(auth);


// GraphQL only accepts JSON data, so not a good choice for file upload
// When creating a post (that contains an image) we proceed in 2 steps :
//  - first we call a normal REST endpoint uploading the file with Multer and returning its URL
//  - then we call the GraphQL endpoint to save the post using the image URL above
app.put("/post-image", (req, res, next) => {
    if (!req.isAuth) {
        throw new Error("Not authenticated");
    }
    if (!req.file) {
        // No file was found in the request so Multer did not create a file on the server
        return res.status(200).json({ message: "No file provided." });
    }
    if (req.body.oldPath) {
        fileUtil.clearImage(req.body.oldPath);
    }
    console.log("Multer created image :");
    console.log(req.file);
    return res.status(201).json({ message: "File uploaded", filePath: 'images/' + req.file.filename });
});


// GraphQL endpoint, all GraphQL queries come through this middleware
// We use "use()" instead of "post()" to allow the use og GraphiQL
// this middleware associates the schema and all its resolvers and does the work to select
// only the fields requested in the incoming requests
app.use("/graphql", graphqlHTTP({
    schema: graphqlSchema,
    rootValue: graphqlResolvers,
    graphiql: true,     // when set, we can access the GraphiQL GUI interface in the browser at GET /graphql 
    customFormatErrorFn(err) {
        // if the error is thrown by our code, express provide it in the "originalError" field
        // it would not exist if there was a syntax error in the GraphQL query for example
        if (!err.originalError) {
            return err;
        }
        const data    = err.originalError.data;
        const message = err.message || "An error occured";
        const code    = err.originalError.code || 500;
        return { message: message, data: data, code: code };
    }
}));

// error-handling middleware
app.use((err, req, res, next) => {
    console.log(err);
    const status = err.statusCode || 500;  // our custom property
    const message = err.message;           // built-in property of Error class
    res.status(status).json({ message: message });
});

// start the web server
mongoose.connect(() => {
    console.log('Starting the web server');
    app.listen(8080);
});
