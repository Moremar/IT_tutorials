const express    = require('express');
const bodyParser = require('body-parser');
const path       = require('path');

// load custom env variables into process.env
const dotenv = require('dotenv');
dotenv.config();

// create Sequelize ORM wrapper above MySQL database
// require dotenv to be setup with the MySQL host, user and password
const sequelize = require('./database');

// import Sequelize models
const Product   = require('./models/product');
const User      = require('./models/user');
const Cart      = require('./models/cart');
const CartItem  = require('./models/cart-item');
const Order     = require('./models/order');
const OrderItem = require('./models/order-item');

// import the custom routes
const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const notFoundController = require('./controllers/error');

/**
 * started with :    npm install
 *                   npm start     (that runs "node server.js")
 *
 * Builds on 07_express_server_mvc, but uses a MySQL database for data storage (instead of a file).
 * It uses the Sequelize Object-Relational-Mapping (ORM) library to create the DB tables interact with the DB.
 * 
 * It now requires a .env file to load with the dotenv module the database parameters (see database.js for details).
 * 
 * It also adds an Orders feature to the app, where we can now order all items from the cart.
 * This creates an order with all ordered products, and empties the cart.
 * 
 * A "users" table is created and the cart and products are attached to a user, but there is no real user management yet.
 * The app only uses a single user (with ID 1) that is created at startup of the app and attached to incoming requests.
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

// middleware to enrich the request with the Sequelize user object
// for now, it just adds the user with ID 1 created at startup (no real user management yet)
app.use((req, res, next) => {
  User.findByPk(1)
    .then((user) => {
      req.user = user;
      next();
    }).catch((err) => {
      console.log('ERROR - Could not retrieve user 1');
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

// DB tables associations using the Sequelize models

// each product belongs to a user (the user who added the product to the store)
// a user can own multiple products, so it is a N-to-1 association
// this creates a foreign key in the table (a "userId" column in the products table)
Product.belongsTo(User, {constraints: true, onDelete: 'CASCADE'});
User.hasMany(Product);
// A user has 1 cart, and a cart belongs to a user, so it is a 1-to-1 association
Cart.belongsTo(User, {constraints: true, onDelete: 'CASCADE'});
User.hasOne(Cart);
// A product can be in many carts, and  a cart can contain many products (N-to-M association)
// N-to-M association require the use of an intermediate table
Product.belongsToMany(Cart, {through: CartItem});
Cart.belongsToMany(Product, {through: CartItem});
// An order belongs to a single user, but a user can have many orders (N-to-1 association)
Order.belongsTo(User, {constraints: true, onDelete: 'CASCADE'});
User.hasMany(Order);
// just like a product and a cart, products and orders are a N-to-M association
Product.belongsToMany(Order, {through: OrderItem});
Order.belongsToMany(Product, {through: OrderItem});

// create all MySQL tables specified by the Sequelize models if they do not exist yet
// set the force parameter to true to force the re-creation of the DB tables
sequelize.sync({ force: false })
  // create the user with ID 1 if it does not exist yet
  // we need a user in all endpoints, and real signup functionality is not implemented in this project
  .then((res) => {
    return User.findByPk(1);
  })
  .then((user) => {
    if (!user) {
      return User.create({ name: 'userdev', email: 'xxxxx' })
        .then((user) => {
          // create a cart for this user, using the auto-generated association method
          return user.createCart();
        });
    }
  })
  .then(() => {
    // only start the server if the DB tables were correctly created
    app.listen(3000);
  }).catch((err) => {
    console.log(err);
  });
