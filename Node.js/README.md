# Node.js Tutorial


## Node.js Overview

- Node.js is a single-threaded Javascript runtime.
- often used to write a web server, but it can run any kind of program (utility scripts, ...)
- use the Google V8 JS engine (developed for Chrome) to analyze and execute JS code
- asynchronous (non-blocking) : to force an order in the function calls, most functions take a callback function as parameter.
- all incoming requests reach the event loop using a single JS thread
- heavy processing tasks are sent for execution by Node.js to a worker pool that uses different threads (for ex a file creation)
- alternatives to Node.js web server are Python (with Django or Flask), PHP (with Laravel) ...


## Installation

- Install Node.js from the official website : https://nodejs.org
- Check version with : `node -v`
- To enter the Node interactive shell (REPL - Read Evaluate Print Loop), run `node`
- To execute a JS file (for example a web server), run `node server.js`  
  The custom `server.js` JS file specifies on which port the server is running (3000 in most examples).  
  To visualize the result webpage, open http://localhost:3000/


## Node.js Event Loop

The event loop is what allows Node.js to perform non-blocking I/O operations despite the fact that JS is single-threaded.  
The event loop is initialized at Node.js startup, and loops through several phases.  
Each phase has a queue of pending callbacks to execute.  
The event-loop will process callbacks in a phase until there is no more callbacks, or the max number or callbacks for an iteration is reached.

**Phase 1 - timers** : execution of callbacks scheduled by `setTimeout()` and `setInterval()`  
**Phase 2 - pending callbacks** : execution of pending I/O callbacks  
**Phase 3 - poll** : retrieve new I/O events and execute some callbacks  
**Phase 4 - check** : execution of callbacks scheduled with `setImmediate()`  
**Phase 5 - close callbacks** : callbacks on close events (for example sockets closed)  


## Node Packet Manager (NPM)

NPM is the package manager for Node modules : https://www.npmjs.com/

It is installed by default when installing Node.  
It gives access to many modules developed by the Node community.  

### NPM CLI

To use a module from NPM, we need to download it locally.  
Packages are downloaded and installed with the `npm` CLI under a `node_modules/` folder.  

Here are the main `npm` commands :

```commandline
npm install mongodb           Install mongodb module locally (in node_modules/ folder)
npm install mongodb --save    Install mongdb locally and save it in package.json
npm install mocha --save-dev  Install a dev-only dependency (tests, build...)
npm install mongodb -g        Install mongodb globally
                              Used for packages offering command line utilities
                              (mongo, markdown, express, mocha...)
npm install                   Install all modules specified in package.json

npm search mongodb            Search all NPM modules about mongodb
npm init                      Create a package.json file for a Node.js project
npm adduser                   Create an NPM account (required to upload a module)
npm publish                   Upload the module to NPM
                              The module must contain package.json and README.md

npm start                     Run the start command from package.json
npm test                      Run the test command from package.json
npm run start-frontend        Run a custom command from package.json
MYVAR=aaa npm start           Run the start command with env var MYVAR set to aaa
                              (accessed in Node code with process.env.MYVAR)

npm outdated                  Should display nothing if up-to-date, tells if update needed
npm outdated -g               Show global packages that are not up-to-date
npm install -g npm            Update npm to the latest stable version
npm update                    Update all dependencies in the project
npm update express            update a local dependency
npm update -g                 Update all global packages to the latest STABLE release
```

### package.json

The NPM configuration of a module is saved in a `package.json` file.  
It contains information about the dependencies of the module and commands that can be ran with NPM.  
Every module contains a `package.json` configuration file.

We can create a `package.json` file for a project with the `npm init` command.  
When adding a module with `npm install <module> --save`, it updates the `package.json` dependencies.  

To install all modules required by a project and specified in a `package.json` file, we can run `npm install`, that will create a `node_modules/` folder and install dependencies under it.

Example of `package.json` file :
```json
{
  "name": "my-web-server",
  "version": "1.0.0",
  "description": "A simple web server",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "author": "Tom Smith",
  "license": "ISC",
  "devDependencies": {
    "nodemon": "^2.0.21"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}
```

## Node.js Modules

Node.js ships with many built-in modules, and many modules built by the community ca be installed with NPM.  
A module can be imported in a project with the `require(packageName)` method.  
Built-in and external modules are imported by their name, and custom local modules are imported by their path.
```commandline
const http = require('http')          // built-in module
const express = require('express')    // 3rd party module
const cards = require('./cards')      // local custom module
```

When we write a custom module, we can export objects and methods by setting the `module.exports` field.  
When calling `require(module)`, we are getting the elements that were exported by this module.

### Built-in modules

- `fs`  for access to the file system
- `http` to create an HTTP server or send HTTP requests
- `https` to create an HTTPS server (with SSL encryption)
- `os` to access OS-specific information
- `path` to construct cross-OS file paths
- `crypto` for cryptography functions

####  http module

This is the module used to create an HTTP server, with the `createServer()` method.  
That method takes in parameter a request listener function that receives the request and response objects.  
The request object is created by Node.js from the HTTP request received on the listened port, and the response object is used by Node.js to generate the HTTP response to send to the requester.

The HTTP server can be started with its `server.listen(port)` method.

It is not imported in an Express project, because Express wraps this `http` module to offer the same functionalities in a more user-friendly way.

#### path module

This is the module to work with directories and file paths in a OS-independant way.  
It exposes many file-related methods :

```javascript
const path = require('path');

path.delimiter                             // delimiter for this OS
path.basename('/app/server/server.js');    // "server.js" base name
path.dirname('/app/server/server.js');     // "/app/server" directory
path.join(__dirname, 'src', 'server.js')   // "./src/server.js" path
```

## Nodemon

`nodemon` is an NPM package installed globally with : `npm install nodemon -g`  
It provides the `nodemon` command that can be used instead of the `node` command to start the web server.  
Everytime the source code is changed, Nodemon will restart the web server automatically.  
This is useful during development to not waste time restarting the web server, but is not used in production.


## Express

Express.js is the most popular framework to build a Node.js web server.  
It can be downloaded from NPM with : `npm install express --save`  
It defines a clear way to structure the code and adding useful functions to perform common tasks (accessing query body, routing, ...).  
Alternatives are vanilla Node.js, or other frameworks like Adonis.js (inspired by Laravel), Sails.js...  

The `express` module exports a function that initializes a web-server configuration object.  
Express is built around the concept of middlewares : each incoming request goes through a pipeline of successive middleware functions that finally create the response.  
Each middleware can enrich the request with information that become available to the next middlewares in the pipeline.  
Many 3rd-party libraries provide middlewares for Express to perform a given task or enrich the incoming request with a given piece of information.

A middleware can be registered in the pipeline with the `use()` method, that takes as parameter a function receiving the incoming HTTP request, the HTTP response and the next middleware.

Each middleware should either send a response with `res.send(obj)`, or forward the request to the next middleware by calling the `next()` callback method.

```javascript
const express = require('express');
const app = express();

// register a middleware that calls the next one
app.use((res, req, next) => {
    next();
});

// register another middleware that sends a response
app.use((res, req, next) => {
    res.send('<h1>Hello</h1>');
});

// create the server from the express config and starts it
app.listen(3000);
```

### body-parser module

The `body-parser` NPM module offers a middleware that parses the body of an incoming request and stores it in a `body` field of the request for the next middlewares to use it.

```javascript
const express = require('express');
const bodyParser = require('body-parser');

const app = express();

// register a middleware to parse the request body
app.use(bodyParser.urlencoded({ extended: true }));
```


### Routing in Express

We can limit a middleware to a given route by adding a 1st parameter in `app.use()` with the path to handle.  
The path is a prefix, not an exact match, so the `/` route matches every request.  
We should call the middleware with more specific path first, and one on `/` last to handle any request that was not handled by any previous middleware.

A middleware for a given route can redirect to another route with `res.redirect('/aaa')`

We can also limit the middleware to a specific HTTP method by replacing `app.use()` by the express method corresponding to the HTTP request, for example `app.get()` or `app.post()`.  
Note that unlike the `use()` method, these HTTP methods use an exact match of the URL, so `/` will not match every incoming request.

For real web servers, we usually use the Express `Router` object to split routes across multiple files.  
We create a `routes/` folder, with a JS file per section of the app.  
Each of these JS files imports Express and instanciate the express router, defines routes for it, and exports it.

```javascript
const express = require('express');
const router  = express.Router();

// register one or more route(s)
router.get('/add', (req, res, next) => {
    res.send('<h1>My page</h1>');
});

// export the router
module.exports = router;
```

This routes module is a custom middleware that can be registered by our express configuration :

```javascript
const myRoutes = require('./routes/myRoutes.js');

app.use(myRoutes);
```

If all routes in a JS routes file use the same prefix, we can add this prefix as a 1st parameter when registering the routes instead of adding it in every route :
```javascript
app.use('/admin', myRoutes);
```

### Serving static files

The files inside the project are not publicly exposed, they cannot be requested from the URL.  
Some files should be available publicly, for example images, fonts, styles...

To allow that, we store all files to expose publicly in a `public/` folder.  
Then we use the `express.static` built-in Express middleware to specify the public folder :

```javascript
// expose public folder
app.use(express.static(path.join(__dirname, 'public')));
```

### Static HTML repsonse

Instead of sending a hardcoding HTML string, we can create some HTML files in a `./views/` folder and reference then as the response :

```javascript
router.get('/add', (req, res, next) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'add-product.html'));
});
```

### HTML Templates

To deliver dynamic HTML content, Node.js supports returning HTML templates, similar to HTML files but containing some templates resolved dynamically by Node.js.  

Several templating engines are supported, all offering similar functionalities (dynamic content, if and for structures...) but with different syntax and philosophy, including :
- **EJS :** HTML syntax with JS templates : `<p><% name %></p>`
- **Pug :** minimal HTML tags and custom template language : `p #{name}` 
- **Handlebars :** HTML syntax with custom template language : `<p>{{ name }}</p>`

These templates are installed from NPM :
```commandline
npm install --save ejs
npm install --save pug
npm install --save express-handlebars
```

The templating engine configuration is done in Express by calling :
```javascript
app.set('view engine', 'pug');
app.set('views', 'views');       // forlder containing the templates
```

Some templating engines (for example Handlebars) are not known by default by Node.js, and need to be registered first :
```javascript
const hbs = require('express-handlebars');

app.engine('hbs', hbs());        // register the template engine
app.set('view engine', 'pug');   // use it
app.set('views', 'views');       // specify the templates location
```

Once the template engine is specified, Node.js can render some templates in response to some requests, by using the `app.render()` method. It takes as parameters the template to render, and the objects to use in the template for dynamic content.
```javascript
res.render('shop', { pageTitle: 'My Shop', products: allProducts });
```

#### Pug template engine

Pug is already integrated in Node.js by default, so it does not need to be imported from code.  
It uses a specific syntax different from HTML (see example project).  

Pug has built-in `if` and `each` keywords to create for loops and if conditions :
```
    if products.length > 0
        each product in products
           p product.name
    else
        p No products to display.
```
Pugs templates can use a layout, which is a common base file used by multiple templates to avoid duplication (for example to include the `head` section and the navbar).

#### EJS templating engine

EJS uses HTML syntax, with some markers to dynamically change the structure of the DOM or add some custom values.  

To insert the value of an object in the template, we use the `<%= value %>` marker :
```html
<p><%= product.description %></p>
```

We can include some JS logic in our template inside the `<% JS code %>` marker.  
This can be used to conditionnally include an HTML block :
```html
<% if (products.length > 0) { %>
    <p>There are products !</p>
<% } else { %>
    <p>There are no products.</p>
<% } %>
```

It can also be used to dynamically repeat an HTML block for each element of an input array :
```html
<% products.forEach(function(product) { %>
    <p> <%= product.title %> costs <%= product.price %> euros. </p>
<% }) %>
```

EJS does not support layouts, but it can define some common blocks (kind of reusable "components") that can be included in other templates with the `<%- include(path) %>` marker that renders non-escaped HTML code.  
The content of these blocks is not necessarily valid HTML, it can open some tags that it does not close, and another include block can close them.
```
<%- include('includes/navbar.ejs') %>
```


## MVC pattern

The Model-View-Controller pattern separates the responsabilities in the app.

- the **Views** are what gets displayed to the user.  
  In a Node.js project, the views are the HTML files and templates.

- the **Models** are in charge of access and management of the data.  
  In a Node.js project, it can be a class by business object used in the app (User, Product, Card...).  
  Only the models interact with the underlying storage solution (database, file system, ...).

- the **Controllers** handle the incoming requests.  
  They call relevant operations from the models, and generate required dynamic information to pass to the views.  
  In a Node.js project, they are the callbacks attached to each route.


## SQL Database

### MySQL driver

Node.js can use a database for its data storage by using a driver package.  
For example, MySQL can be installed from their website on the local machine (Communnity Server + Workbench GUI).
Then it can be used from the Node.js app with the `mysql2` client driver :

```
npm install mysql2 --save
```

A connection is required to send a query to the MySQL database.  
We could open and close a connection for each request, but it quickly becomes inefficient.  
Instead we can create a connection pool that gets reused by incoming queries.  
The connection pool must know the database host, user (for example `root` created during MySQL installation) and database schema.

##### database.js

```javascript
const mysql = require('mysql2');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'mypassword',
  database: 'schemanodejs'
});

// return a promise so query results can be chained with .then()
module.exports = pool.promise()
```

Using this connection pool, we can send raw SQL queries to the database and receive the results in a promise.  
Queries with user-defined arguments should use parametrized queries, letting the MySQL driver sanitize the arguments to avoid SQL injection :

##### server.js

```javascript
const db = require('./database');

// query with no parameter
db.execute('SELECT * FROM products')
  .then( (res) => {
    console.log(res[0]);  // query result
    console.log(res[1]);  // metadata
  }).catch( (err) => {
    console.log(err);
  });

// parametrized query
db.execute('INSERT INTO products(title, price, image_url, description) '
         + 'VALUES (?, ?, ?, ?)', 
           [ this.title, this.price, this.imageUrl, this.description ]
    .then( ... )
    .catch( ... );
```

### Sequelize

Sequelize is an ORM (Object-Relational Mapping) library for SQL databases in Node.js.  
It abstracts away the SQL queries, by exposing models (one JS class per database table) used as a handle to the DB.  
We can call static methods of these model classes, or instantiate them and call object methods to execute SQL code in the DB.

``` commandline
npm install sequelize --save
```

##### database.js

```javascript
const Sequelize = require('sequelize').Sequelize;

const sequelize = new Sequelize(
      'schemanodejs', 'root', 'mypassword',
      {dialect: 'mysql', 'host': 'localhost'});

// The connection pool is now managed by Sequelize under the hood
module.exports = sequelize;
```

Models can be completely rewritten as Sequelize models.  
For example a `Product` Sequelize model can be created to wrap a `products` table in MySQL, and insert/update/delete rows.  
The model definition specifies the database table fields.

##### product.js

```javascript
const Sequelize = require('sequelize');   // sequelize package
const sequelize = require('./database');  // sequelize instance wrapping the DB

// define the table fields of a "products" table
const Product = sequelize.define('product', {
  id: { type: Sequelize.INTEGER, allowNull: false, primaryKey: true, autoIncrement: true },
  title: { type: Sequelize.STRING, allowNull: false },
  price: { type: Sequelize.DOUBLE, allowNull: false },
  imageUrl: { type: Sequelize.STRING, allowNull: false },
  description: { type: Sequelize.STRING, allowNull: false }
});

module.exports = Product;
```

In the main server code, we can create the DB tables with the `sync()` function.  
By default it only creates the table if it does not exist.  
The `force` option can be used to always re-create the tables (useful for dev to pick-up table columns changes).

##### server.js

```javascript
// create all MySQL tables specified by the Sequelize models if they do not exist yet
sequelize.sync({force: false})
    // start the web server if the DB tables were correctly created
  .then((res) => {
    console.log(res);
    app.listen(3000);
  }).catch((err) => {
    console.log(err);
  });
  ```

Node.js controllers can use these models to create/update/delete rows in the DB.  
Model classes expose `.build()` to create a JS instance, and `.create()` to create the JS instance and save it in the DB.
Sequelize methods return Promise instances, that can be chained with `.then()` and `.catch()` :

```javascript
Product.create({title: myTitle, price: myPrice})
       .then(  (res) => { console.log(res); } )
       .catch( (err) => { console.log(err); } );

Product.findAll({ where: { price: { [Op.gt]: 100.00 } } })
       .then(  (res) => { console.log(res); } )
       .catch( (err) => { console.log(err); } );
```

Sequelize lets us define 1-to-1, 1-to-N, N-to-1 or N-to-M relations between models.  
We can for example specify that each Product belongs to a User (N to 1) by calling (usually in `server.js` before the sync):

```javascript
Product.belongsTo(User, {constraints: true, onDelete: 'CASCADE'});
User.hasMany(Product);
```

This will create a `userId` column in the Product table, with a foreign key to the User table.  
It also generates association methods in the User model, such as the `createProduct()` method that creates a new product and attaches the ID of the user object calling the method in the `userId` field.

To create a N-to-M association, we need an intermediate table.  
If we have a cart that can contain many products, and a product that can be in many carts, we can create 3 models `Product`, `Cart` and `CartItem`, and associate them with :

```javascript
// many-to-many relations use an intermediate table
Product.belongsToMany(Cart, {through: CartItem});
Cart.belongsToMany(Product, {through: CartItem});
```

This will create methods in `Cart` and `Product` models to access all associated products/carts.  
The intermediate element in the `CartItem` model can be accessed via the `cartItem` property of every cart or product instance.


## No-SQL Databases

### MongoDB driver

To start a MongoDB server, we can either use a local instance (with the `mongod` executable) or create a new project in the cloud with Atlas (see full MongoDB guide).  
In any case, we should have a MongoDB server running and a valid username/password pair to access it.

The MongoDB Node.js driver lets us interact with this database from the Node.js code :

```commandline
npm install mongodb --save
```

##### database.js

```javascript
const mongodb = require('mongodb');

// internal variable, exposed via the getDb() method
let _db;

const connect = (callbackFn) => {
    const uri = "mongodb+srv://myuser:mypassword@myHost/?retryWrites=true&w=majority";

    const mongoClient = new mongodb.MongoClient(uri).connect()
    .then((client) => {
        console.log('Connected to the MongoDB server');
        _db = client.db(mongoDatabase);
        callbackFn();
    })
    .catch((err) => {
        console.log(err);
    });
};

const getDb = () => {
    if (_db) {
        return _db;
    }
    throw 'Need to call connect() before accessing the database';
}

exports.connect = connect;
exports.getDb = getDb;
```

The model of the Node.js app can then perform actions in the MongoDB database using the handler exposed by the `getDb()` method.

For example, to create a user in a `users` collection, we can use the following methods, that return promises that the caller can react to in a `then()` block :

```javascript
const mongo = require('../database');

// create with an insert MongoDB command
const db = mongo.getDb();
return db.collection('users').insertOne({ 
  'name': 'userdev',
  'email': 'xxxxx'
});

// create with an upsert MongoDB command
const db = mongo.getDb();
return db.collection('users').updateOne(
    { 'email': 'xxxxx' },     // use the email as the unique identifier
    { $set : { 'name': 'userdev' } } ,
    { upsert: true }
);
```

In MongoDB, documents have an ID of class `ObjectId` that can be used for SQL-like associations between collections.  
MongoDB documents can also contain nested objects, which can be an alternative to associations.  
This is a good solution when we want a snapshot of a document at one point in time, but it is creating an overhead if the duplicate nested document must be updated when the original document is modified.


### Mongoose

Mongoose is an ODM (Object-Document Mapping) library for MongoDB in Node.js (like the Sequelize ORM for SQL databases).  
It abstracts away the MongoDB commands, so we only use the Mongoose models to interact with the MongoDB database.  

``` commandline
npm install mongoose --save
```

Mongoose already ships with a built-in `connect()` method to create a connection to the MongoDB database :

##### server.js 
```javascript
const mongoose = require('mongoose');

[ ... ]

const mongoUser     = process.env.MONGODB_USER;
const mongoPassword = process.env.MONGODB_PASSWORD;
const mongoHost     = process.env.MONGODB_HOST;
const mongoDatabase = process.env.MONGODB_DATABASE;
const mongoUri = "mongodb+srv://" + mongoUser + ":" + mongoPassword
          + "@" + mongoHost + "/" + mongoDatabase + "?retryWrites=true&w=majority";

mongoose.connect(mongoUri)
.then((client) => {
    console.log('Connected to the MongoDB server');
    app.listen(3000);
})
```

The models can now be Mongoose models, that define a schema for a collection.  
They specify the types of fields in the collection, and support nested documents.  
Fields can also be references to a document in another collection.  
It is also possible to add custom methods to the model by defining them in `schema.methods` :

#### product.js

```javascript
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    cart: { items: [{
        productId: {type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true},
        quantity: {type: Number, required: true}
    }]}
});

// example of custom model method
userSchema.methods.clearCart = function() {
  this.cart.items = [];
  return this.save();
}

module.exports = mongoose.model('User', userSchema);   // create a "users" collection
```

The Mongoose model exposes methods to interact with the collection, suche as `find()`, `findById()`, `findByIdAndUpdate()`, `findByIdAndDelete()` ...

Mongoose also exposes the `populate()` method, that replaces a reference ObjectId field in the result documents by their corresponding document :

```javascript
Product.find()
// replace "userId" by a doc from the "users" collection
.populate('userId') collection
.then((enrichedProducts) => {
  [ ... ]
})
```
## Cookies and Sessions

#### Cookies

Cookies are data sent by the server along with a response to a request.  
Cookies are stored by the client (in the browser) and are attached to all later requests to that domain.  
They are used for example to store authentication tokens after login.

A cookie can be sent to the client by setting the `Set-Cookie` header in a HTTP response :

 ```javascript
 res.setHeader('Set-Cookie', 'mycookieval=aaa');
 ```

The received cookie is saved in the browser (in Chrome : `Developer Tools > Application > Cookies`) until the browser is closed.  
All cookies stored in the browser for a given domain name are attached to each following request sent to that domain name under the `Cookie` header.  

A cookie value in the request can be retrieved from Node.js with :

```javascript
req.get('Cookie')
```

A better way to retrieve cookies is to use the `cookie-parser` middleware :

```javascript
const cookieParser = require('cookie-parser');

// middleware to parse cookies
app.use(cookieParser());

// example middleware to access the cookie
app.use((req, res, next) => {
  console.log('COOKIE: ' + req.cookies.mycookieval );
  next();
});
```

Note that cookies can be viewed and modified by the client from the browser, so the app should not store sensitive data in cookies.  
For example, it should never store a boolean to know if the user is logged or not.


#### Sessions

Sessions are objects stored on server-side to identify a connection from a user, and share information (for example the login information) between requests from that user.  

When an HTTP request is received by the server, a session can be created on server-side.  
Each incoming request can indicate what session it belongs to.  

This can be done using a cookie : 
- at login, the server creates a session, and sends a hash of the session ID as a cookie
- the client stores this session ID in a cookie in the browser
- the session ID cookie is attached to the next requests from that user
- the server checks this cookie to confirm the session and enriches the request with session data

Sessions can be managed in Express with the `express-session` package.  
Values stored in `req.session` can be accessed from later requests belonging to the same session.  
Under the hood, the `express-session` middleware creates a `connect.sid` cookie in the client browser when we first use the session.  
For later requests, this session ID is read by the session middleware that initializes the `req.session` object.

We can specify a session store to save the session related data (in-memory by default).  
For example `connect-mongodb-session` provides a session store in MongoDB.

```commandline
npm install express-session --save
npm install connect-mongodb-session --save
```
##### server.js

```javascript
// import the session package
const session = require('express-session');
const mongoStore = require('connect-mongodb-session');

// create a MongoDB session store
const sessionStore = new mongoStore(session)({
  uri: "mongodb+srv://<USERNAME>:<PASSWORD>@<HOST>/<DBNAME>",
  collection: "sessions"
});

// configure the middleware for session management
app.use(session({
  secret: 'MY_SECRET_STRING',    // should come from a config file in a prod env
  resave: false,                 // do not resave at every request
  saveUninitialized: false,      // do not save when nothing changed
  store: sessionStore            // store to save session data (in-memory by default)
}));

// example middleware storing a value in the session
app.use((req, res, next) => {
  req.session.mySessionVal = "bbb";
  console.log(req.session);
  next();
});
```

A session can be destroyed on logout with the `req.session.destroy(callback)` method.  
This will remove the session object on server side, not the cookie on client side.  
The cookie on client side will be removed automatically by the browser on expiration or when the browser is closed.


## Authentication

Authentication is required to allow access to specific pages only to specific users.  
Authentication is performed via a login request, containing the email and password.  
The server confirms the credentials, and creates a session on server-side, so the next requests from that user do not need to contain the login credentials.  

Passwords should not be saved in clear text in the database.  
They should be stored as hashes, and on login the provided password should be compared to the stored hash.  
The `bcrypt` package offers these functionalities :

```commandline
npm install --save bcryptjs
```

```javascript
const bcrypt = require("bcryptjs");

// create a hash for a password
bcrypt.hash("mypassword", 12)
.then((hashedPassword) => {
  // save in DB
})

// compare a password with a hash
bcrypt.compare("mypassword", hashedPassword)
.then((ok) => {
  if (ok) {
    // password matches
  }
})
```

### Route Protection

Some routes can be restricted user that are logged in, or to specific users.  
The best way to implement that is to create a custom middleware function to execute before the protected route.  
If the route access is not granted, the middleware redirects to another page.

##### is-auth.js - custom middleware
```javascript
module.exports = (req, res, next) => {
    // any kind of check on session variables can be done here
    if (!req.session.isAuthenticated) {
        // Access refused
        return res.redirect("/login");
    }
    // Access granted
    next();
};
```

##### admin.js - controller
```javascript
const isAuth = require("../middlewares/is-auth");

// can list multiple middlewares to execute from ledt to right
router.post('/add-product', isAuth, productsController.postAddProduct);
```

### Cross-Site Request Forgery Protection

If a website only relies on a cookie storing the session ID for authentication after login, it is vulnerable to Cross-Site Request Forgery (CSRF) attack.  
This attack consists in tricking a user to send a forged HTTP request to the website while it has a session active, so his cookie with the session ID will be attached to the request, and the website will treat it as a legit request.  

This can be done by tricking the user to :
- click a forged link (GET method)
- open a page with a malicious `<img>` tag with size 0 and the forged URL as its `src` field (GET method)
- open a page with a malicious `<form>` tag with hidden fields for the body parameters and a `<script>` tag to submit the form (POST method)

The attacker does not know the victim's cookie, but relies on the fact that the cookie will be attached automatically to the forged request to impersonate the victim.  
It can be used for example to change the password of the victim, so the attacker can then login normally with the new password.

A simple way to protect against CSRF attacks is to set the cookie as "Same-Site" to only attach it to requests initialized from the same website.

A more robust solution is to use a CSRF token, generated randomly and delivered to the user as a hidden field of the form for the operation he wants to do (password reset, business object creation/modification/deletion, ...).  
This CSRF token is stored on the backend along with the session, and operations are executed only if the token received from the user matches the one stored on server-site.  
The attacker forging a request cannot know this token value, so the forged request will not be executed.  
Obviously, the CSRF token should not be stored as a cookie, otherwise it gets automatically attached to the forged request in the same way as the session cookie !

CSRF tokens can be generated in Node.js with `csurf` package :

```commandline
npm install csurf --save
```

```javascript
const csurf = require('csurf');

// middleware for CSRF protection (must come after the session middleware)
app.use(csurf());
```

At every received POST request, `csurf` will compare the CSRF token.  
This CSRF token is given by `req.csrfToken()` (made available by csurf) and must be added to the view in a hidden `<input>` tag with name `_csrf` :

```html
<!-- CSRF token in a hidden input -->
<input type="hidden" name="_csrf" value="<%= csrfToken %>" />
```

Instead of manually adding the `csrfToken` variable in every `res.render()` call, we can leverage Express's `locals`, letting us add some local variables to every request and passing them to the view :

```javascript
app.use((req, res, next) => {
  // add csrfToken variable available to every views
  res.locals.csrfToken = req.csrfToken();
  next();
});
```

**NOTE :** `csurf` package is now deprecated, production projects should use alternatives like `tiny-csrf` or `csrf-csrf` packages !


### Password Reset

We can allow password reset by sending an email to the user with a password reset link.  
This link should include a temporary token generated and stored in the database in the user object.  
When the link is clicked, the server checks the token, and gives a form allowing to change the password.  
When this form is submitted, the server checks again the token, update the password and remove the token from the database.  

We can use the `crypto` built-in package to generate this token.

```javascript
const crypto = require('crypto');

crypto.randomBytes(32, (err, buffer) => {
  if (err) {
    console.log(err);
  } else {
    const token = buffer.toString("hex");
    // save the token in DB, create a link with this token and send it by mail
  }
});
```


## User feedback

We often want to send a feedback to the user when an action was performed or an error occured.  
This is not straight-forward because a call to `redirect()` generates a new requests so loses the current request.  
We could store a message in the session, but we want this message to stay only for the time to display it.

Express offers the `connect-flash` package for that purpose :

```commandline
npm install connect-flash --save
```

```javascript
const flash = require('connect-flash');

// initialize connect-flash for temporary messages
// must be after the middleware to initialize of the session
app.use(flash());
```

A message can be flashed to the session with `req.flash('myError', 'An error occured !');`.  
This message can then be retrieved with `req.flash('myError')`, and it gets removed from the session.  
A common use is to retrieve the message and pass it as a parameter to the `req.render()` function.


## User Input Validation

Front-end frameworks (Angular, React...) can perform some input validation on client-side to improve user experience.  
However, front-end code can be modified by the user, so validation on server-side is always required.

Validation in Express can be done with the `express-validator` package :

```commandline
npm install express-validator --save
```

A validation middleware can be added to POST routes to check the values received in the request.  
The `check()` middleware gives access to the entire request.  
The `body()`, `header()` and `cookie()` middleware only check the request body/headers/cookies.

```javascript
// check that the "email" field is a valid email address
router.post('/signup', 
    check('email').isEmail().withMessage('The email is invalid.'),
    authController.postSignup);
```

If the validation fails, the error is added to the request and can be accessed by the next middlewares with `validationResult(req)` :

```javascript
exports.postSignup = (req, res, next) => {
  // retrieve fields validation results from the check() middleware
  const validationErrors = validationResult(req);
  if (!validationErrors.isEmpty()) {
    // 422 : Validation failed status
    return res.status(422).render('signup', { pageTitle: 'Signup', errorMessage: validationErrors.array()[0].msg });
  }
  // logic to signup when no error
}
```

The `expres-validator` package is a wrapper above the `validator.js` library, so it exposes all its validations :  
`isEmail`, `isDecimal`, `isIP`, `isJSON` ... (full list on `validator.js` GitHub page).

We can write custom validators with the `.custom()` method of the `check()` middleware :

```javascript
// check that the "email" field is a valid email address
router.post('/signup', 
    check('email')
        .isEmail().withMessage('The email is invalid.'),
        .custom((value, {req}) => { 
            if (value === 'test@test.com') {
                throw new Error('Forbidden email address.');
            }
            return true;
        }),
    authController.postSignup);
```

A validator can be asynchronous, in that case it should return a promise.  
The validation will wait for the promise to resolve, and in case of rejection it will fail the validation :

```javascript
router.post('/signup', 
    check('email')
        .isEmail().withMessage('The email is invalid.')
        .custom((value, { req }) => {
            // asynchronous custom validation
            return user.findOne({ email: value })
              .then((user) => {
                if (user) {
                    // email already in use
                    return Promise.reject('An account already exists for this email.');
                }
              });
        }),
    authController.postSignup);
```

The validation also provides methods to sanitize or normalize the input fields.  
For example we can trim a field, or remove the sub-address of an email address.

```javascript
router.post('/signup', 
    check('email')
        .isEmail().withMessage('The email is invalid.')
        .normalizeEmail(),
    authController.postSignup);
```


## Error Handling

Depending on the type of error, several strategies can be used to handle errors :
- return the same page and display an error message, for example if user input is invalid in a form
- return a custom page for that error (404 when requesting an unknowned page, 500 when a server error occured...)

Errors are handled in `try {} catch {}` blocks for synchronous code, and `.then().catch()` blocks for asynchronous code.  
To avoid having similar `.catch()` block in many middlewares handling the same type of error (for example a DB issue), we can instead create a custom error from our middleware and pass it to the `next()` method.  
When given an error parameter, `next(err)` will skip all following middlewares and go directly to an error-handling middleware.

```javascript
// logic inside a middleware :
const error = new Error('A database error occured');
error.httpStatusCode = 500;
next(error);
```

An error-handling middleware can be defined in `server.js` after the default middleware returning a 404 to all incorrect requests.  
It takes 4 parameters instead of 3, by receiving the error as a 1st parameter (so Express knows it is an error-handling middleware).

```javascript
// error-handling middleware
// accessed when calling next(error)
app.use((error, req, res, next) => {
    console.log('Server error occured in call ' + req.method + ' ' + req.url);
    console.log(error);
    // use an EJS template
    res.render('server-error', {pageTitle: 'Server error'});
});
```

If an error is thrown in a middleware, Express will automatically reach this error-handling middleware (it calls `next(err)` for us).  
That is not the case if the error is thrown asynchronously inside a `then()` or `catch()` promise block.


## File upload / download

The `body-parser` middleware parses URL-encoded parameters in the request body (encoded as string).  
This is good to parse forms with the default `application/x-www-form-urlencoded` encoding type.  

To upload a file to the server, the form in the view must have the `multipart/form-data` encoding type to specify that the data is sent in binary format :

```html
<form class="edit-product-form"
      action="/admin/edit-product"
      method="POST" 
      enctype="multipart/form-data" >

  <div class="form-control">
      <label>Image</label>
      <input type="file" name="image" id="image" />
  </div>

   <!-- other inputs and submit button -->
</form>
```

We parse this mutipart form data from the request with the `multer` middleware.  
Multer can configure the storage details (folder and naming) and a filter to limit the accepted files.  
If we have a single file upload in the app, we can use `multer().single(filename)`.

```commandline
npm install multer --save
```

```javascript
// specify storage folder and file naming on the server
const uploadStorage = multer.diskStorage({
  destination: (req, file, cb) => { cb(null, './uploads/images/'); },
  filename:    (req, file, cb) => { cb(null, new Date().getTime().toString() + '-' + file.originalname); }
});

// filter limiting the accepted files to PNG and JPG images
const uploadFilter = (req, file, cb) => {
  const validFormat = file.mimetype === 'image/png' || file.mimetype === 'image/jpg' || file.mimetype === 'image/jpeg';
  cb(null, validFormat);
};

// middleware to extract the file in the "image" body field if available
app.use(multer({storage: uploadStorage, fileFilter: uploadFilter}).single("image"));
```

In the middleware in charge of the route receiving the file, we can access the `req.file` object giving some info about the file saved by Multer.  

```json
{
  fieldname: 'image',
  originalname: 'car.png',
  encoding: '7bit',
  mimetype: 'image/png',
  destination: './uploads/',
  filename: '1683253893212-car.png',
  path: 'uploads/images/1683253893212-car.png',
  size: 2058560
}
```

In the DB, we would only store the `path` of the image on the server.  
This path can be used as a `href` to display an image from a view with the `<image>` tag.  
For that, the folder containing the image should either be publicly accessible, or a route should exist for that path.

To download a file from the server we can stream it to avoid loading the entire file in server memory :

```javascript
app.get('/download', function(req, res) {
  const fileName = 'car.png';
  const filePath = path.join('uploads', 'images', fileName);
  
  res.setHeader('Content-disposition', 'attachment; filename=' + fileName);
  res.setHeader('Content-type', 'application/png');

  const readStream = fs.createReadStream(filePath);
  readStream.pipe(res);
});
```

## Payment with Stripe

Stripe is a 3rd-party payment processing platform that can be used to add payment in an app.  
We can create an account for free at `https://stripe.com` and access test API keys.

We can use Stripe to externalize the payment system.  
For each payment, we create a session in the Stripe API, with the details of the products to pay for.  
The user is redirected to a Stripe web page to enter his payment information.  
On cancel or success, Stripe redirects the user to our app.

```commandline
npm install stripe --save
```

The button to pay needs to call the Stripe API with a session ID.  
The controller showing the page with a pay button should create this Stripe session and attach the session ID to the page :

```javascript
// configure stripe with the Stripe API secret key of our account
const Stripe = require("stripe");
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

exports.getCheckout = (req, res, next) => {
  let products = [];
  // logic to populate the products
  // create and configure a Stripe session
  return stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    line_items: products.map(item => {
      // items must have this specific format
      return {
        price_data: {
          currency: "usd",
          unit_amount: item.price * 100,    // in cents
          product_data: {
            name: item.title,
            description: item.description
          }
        },
        quantity: item.quantity
      };
    }),
    mode: "payment",
    success_url: req.protocol + "://" + req.get("host") + "/checkout/success",
    cancel_url: req.protocol + "://" + req.get("host") + "/checkout/cancel"
  })
  .then((session) => {
    res.render('checkout', {
      ...
      sessionId: session.id,
      stripePublicKey: process.env.STRIPE_PUBLIC_KEY
    });
  });
};
```

This Stripe session ID can be used from the view to redirect to Stripe on button click :

```html
  <div>
      <button class="btn" id="order-btn">Pay</button>

      <!-- Stripe 3rd party script for payment -->
      <script src="https://js.stripe.com/v3/"></script>

      <script>
          // create a handler to call the Stripe API
          var stripe = Stripe("<%= stripePublicKey %>");
          // make the pay button call the Stripe API with the provided session
          var orderBtn = document.getElementById("order-btn");
          orderBtn.addEventListener("click", function() {
              stripe.redirectToCheckout({ sessionId: "<%= sessionId  %>" });
          });
      </script>
  </div>
```



## Background requests

Express controllers are not limited to sending an HTML page with `res.render()` or `res.redirect()`.  
We can also have the client-side code sending a background HTTP request, and the server responding with JSON data.  
The client code can use a JS script with the `fetch()` method (successor of `XMLHttpRequest`).  
It can use any HTTP verb, like `GET`, `DELETE`, `POST`, `PUT` ...   
The server-side controller can respond with a JSON object with `res.json()` :

##### views/product-admin.ejs (HTML template file)

```html
<button type="button" onclick="deleteProduct(this)">Delete</button>

[...]

<script src="/js/admin.js"></script>
```

##### public/js/admin.js

```javascript
const deleteProduct = (btnElement) => {
    // access the product ID and CSRF tokens
    const productId = btnElement.parentNode.querySelector('[name=productId').value;
    const csrf      = btnElement.parentNode.querySelector('[name=_csrf').value;
    
    // send the HTTP request (fetch is a modern replacement of XMLHttpRequest)
    fetch("/admin/product/" + productId, {
        method: "DELETE",
        headers: { "csrf-token": csrf }
    })
    .then((response) => {
        return response.json();
    })
    .then((result) => {
        // do something with the response
    })
    .catch((err) => {
        console.log(err);
    });
};
```


## Useful Node.js libraries

### dotenv

Dotenv is a module that loads environment variables from a `.env` file into the `process.env` member variable, along with all other environment variables loaded by Node.js.  

This can be useful to store  in the `.env` file all access keys, credentials or environment-specific parameters, properly separated from the code.  
This configuration file can be listed in the `.gitignore` file to be excluded from the git repository.

```commandline
npm install dotenv --save
```
##### .env

```javascript
MYSQL_HOST="localhost"
MYSQL_USER="root"
MYSQL_PASSWORD="mypassword"
```

These values can be accessed from the `process.env` variable in the Node.js code :

```javascript
const dotenv = require('dotenv');
dotenv.config();
console.log('Host : ' + process.env.MYSQL_HOST);
```


### nodemailer

The `nodemailer` package makes it easy to send emails in Node.js code.  
Node.js does not contain a mail server, so we need to use a 3rd party mail server.  
SendGrid is a good choice for a test project, as it offers a free plan for up to 100 mails/day.  
Create a SendGrid account and get an API key from Settings > Create API Key.  

```commandline
npm install nodemailer --save
npm install nodemailer-sendgrid-transport --save
```

```javascript
const nodemailer = require('nodemailer');
const sendgrid = require('nodemailer-sendgrid-transport');

// configure nodemailer with the SendGrid 3rd party mail server
const transporter = nodemailer.createTransport(sendgrid({
  auth: { api_key: 'API_KEY_FROM_SENDGRID' }
}));

// send an email with nodemailer
transporter.sendMail({
  to: 'xxx@xxx.com',
  from: 'yyy@xxx.com',  // must be registered as an identity in SendGrid
  subject: 'Signup succeeded',
  html: `<h1>Signup succeeded, you can now login.</h1>`
})
.then((result) => { console.log(result); });
```


### pdfkit

The `pdfkit` package lets us create PDF files.

```commandline
npm install pdfkit --save
```

```javascript
const fs = require('fs');
const PDFDocument = require('pdfkit');

// Create a new PDF document in memory
const doc = new PDFDocument();

// Pipe the PDF document to a writable stream (a file here)
doc.pipe(fs.createWriteStream('example.pdf'));

// Generate the PDF file content
pdfDoc.fontSize(24).text("My title", { underline: true });
pdfDoc.fontSize(12).text("   ");
pdfDoc.text("Some text here");

// Finalize the PDF and end the stream
doc.end();
```