const express      = require('express');
const bodyParser   = require('body-parser');
const multer       = require('multer');
const cookieParser = require('cookie-parser');
const session      = require('express-session');
const mongoStore   = require('connect-mongodb-session');
const path         = require('path');
const csurf        = require('csurf');
const flash        = require('connect-flash');

// load custom env variables into process.env
const dotenv = require('dotenv');
dotenv.config();

// database configuration (must come after the .env file is loaded)
const mongoose = require('./database');

// import the custom routes
const adminRoutes = require('./routes/admin');
const shopRoutes  = require('./routes/shop');
const authRoutes  = require('./routes/auth');
const errorController = require('./controllers/error');
const User = require('./models/user');

/**
 * started with :    npm install
 *                   vim .env               (create the .env file with DB and SendGrid config)
 *                   mkdir uploads
 *                   mkdir uploads/images
 *                   mkdir uploads/invoices
 *                   npm start              (that runs "node server.js")
 *
 * Builds on 10_express_server_mongoose, and adds user management with signup/login/logout/password reset.
 * It also adds file upload and download with multer.
 * 
 * The uploads/images/ and uploads/invoices empty folders must be created.
 * 
 * The .env configuration file should look like :
 * 
 *   MONGODB_HOST="xxxxx"
 *   MONGODB_USER="xxxxx"
 *   MONGODB_PASSWORD="xxxxx"
 *   MONGODB_DATABASE="xxxxx"
 *   SENDGRID_API_KEY="xxxxx"
 *   SENDGRID_FROM_EMAIL="xxxxx"
 */


// create the web server config object
const app = express();

// setup express to use EJS templating engine
app.set('view engine', 'ejs');
app.set('views', 'views');

// create a MongoDB session store
const sessionStore = new mongoStore(session)({
  uri: mongoose.getMongoUri(),
  collection: "sessions"
});

// expose public folder
app.use(express.static(path.join(__dirname, 'public')));

// expose all product images uploaded with Multer (all users can see all product images)
// we specify the "/uploads/images" path to keep it in the image path
app.use('/uploads/images/', express.static(path.join(__dirname, '/uploads/images/')));

// middleware to parse the body of every incoming request
app.use(bodyParser.urlencoded({ extended: true }));

// middleware to extract the file in the "image" body field if available
// useful for the product upload POST requests
const uploadStorage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, './uploads/images/'); },
  filename:    (req, file, cb) => { cb(null, new Date().getTime().toString() + '-' + file.originalname); }
});
const uploadFilter = (req, file, cb) => {
  const validFormat = file.mimetype === 'image/png' || file.mimetype === 'image/jpg' || file.mimetype === 'image/jpeg';
  cb(null, validFormat);
};
app.use(multer({storage: uploadStorage, fileFilter: uploadFilter}).single("image"));

// middleware to parse cookies
app.use(cookieParser());

// configure the middleware for session management
app.use(session({
  secret: 'MY_SECRET_STRING',    // should come from a config file in a prod env
  resave: false,                 // do not resave at every request
  saveUninitialized: false,      // do not save when nothing changed
  store: sessionStore            // where to store the session data (in-memory by default)
}));

// middleware for CSRF protection : CSRF token creation and validation
// need to be after the initialization of the session
app.use(csurf());

// initialize connect-flash for temporary messages
// need to be after the initialization of the session
app.use(flash());

// middleware to enrich the request with the user Model instance
// it uses the user stored in the session to instanciate a Mongoose User instance
// this is required to call Mongoose custom methods on it
app.use((req, res, next) => {
  if (req.session.isAuthenticated) {
    User.findOne({ _id: req.session.user._id })
    .then((user) => {
      req.user = user;
      next();
    }).catch((err) => {
      console.log('ERROR - Could not retrieve user');
      console.log(err);
    });
  } else {
    next();
  }
});

// middleware to log every incoming request
app.use((req, res, next) => {
    console.log(req.method + ' ' + req.url);
    next();
});

// middleware to add some local variables available to all response views
app.use((req, res, next) => {
  // add isAuthenticated and csrfToken available to every views
  res.locals.isAuthenticated = req.session.isAuthenticated;
  res.locals.csrfToken = req.csrfToken();
  next();
});

// register the routes middlewares
app.use('/admin', adminRoutes);      // with a route prefix
app.use(shopRoutes);                 // without a route prefix
app.use(authRoutes);

// return a 404 for unsupported requests
app.use(errorController.getNotFoundPage);

// error-handling middleware
// accessed when calling next(error)
app.use(errorController.getServerErrorPage);


// start the web server
mongoose.connect(() => {
    console.log('Starting the web server');
    app.listen(3000);
});
