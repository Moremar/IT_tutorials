const path       = require('path');
const express    = require('express');
const bodyParser = require('body-parser');
const db         = require('./db')

const productRoutes = require('./routes/products');
const authRoutes    = require('./routes/auth');

const app = express();

app.use(bodyParser.json());
app.use('/images', express.static(path.join('backend/images')));

app.use((req, res, next) => {
  // Set CORS headers so that the React SPA is able to communicate with this server
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,POST,PUT,PATCH,DELETE,OPTIONS'
  );
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

app.use('/products', productRoutes);
app.use('/', authRoutes);

db.initClient(
  (err, client) => {
    if (err) {
      console.log(err);
    } else {
      // starts the server only if the DB was initialized correctly
      app.listen(3100);
    }
  }
);