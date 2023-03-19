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


### HTML response

Instead of sending a hardcoding HTML string, we can create some HTML files in a `./views/` folder and reference then as the response :

```javascript
router.get('/add', (req, res, next) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'add-product.html'));
});
```