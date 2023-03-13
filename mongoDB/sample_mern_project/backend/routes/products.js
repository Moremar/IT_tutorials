const Router = require('express').Router;
const mongodb = require('mongodb');
const db      = require('../db');

const router = Router();
const Decimal128 = mongodb.Decimal128;
const ObjectId   = mongodb.ObjectId;


// Get list of products
router.get('/', (req, res, next) => {

  // if a page is requested, get that page (each page has 10 products)
  const queryPage = req.query.page ? +(req.query.page) : 1;
  const pageSize = 10;

  let products = [];

  db.getClient()
    .db("shop")
    .collection("products")
    .find()
    .sort({price: -1})
    .skip((queryPage - 1) * pageSize)
    .limit(pageSize)
    .forEach(
      (product) => {
        product.price = product.price.toString();
        product._id = product._id.toString();
        products.push(product);
      }
    )
    .then(
      () => {
        res.status(200).json(products);
      }
    )
    .catch(
      (err) => {
        console.log(err);
        res.status(500).json({ message: 'An error occurred when retrieving the products from the database.' });
      }
    );
});

// Get single product
router.get('/:id', (req, res, next) => {
  db.getClient()
    .db("shop")
    .collection("products")
    .findOne({_id: new ObjectId(req.params.id)})
    .then(
      (product) => {
        console.log('Get single product');
        console.log(product);
        product.price = product.price.toString();
        product._id = product._id.toString();
        res.status(200).json(product);
      }
    )
    .catch(
      (err) => {
        console.log(err);
        res.status(500).json({ message: 'An error occurred when retrieving the product from the database.' });
      }
    );
});

// Add new product
// Requires logged in user
router.post('', (req, res, next) => {
  const newProduct = {
    name: req.body.name,
    description: req.body.description,
    price: Decimal128.fromString(req.body.price.toString()),
    image: req.body.image
  };

  db.getClient()
    .db("shop")
    .collection("products")
    .insertOne(newProduct)
    .then(
      (mongoDbRes) => {
        console.log(mongoDbRes);
        res.status(201).json({ message: 'Product added', productId: mongoDbRes.insertedId });
      }
    )
    .catch(
      (err) => {
        console.log(err);
        res.status(500).json({ message: 'An error occurred when inserting the product in the database.' });
      }
    );
});

// Edit existing product
// Requires logged in user
router.patch('/:id', (req, res, next) => {
  const updatedProduct = {
    name: req.body.name,
    description: req.body.description,
    price: Decimal128.fromString(req.body.price.toString()), // store this as 128bit decimal in MongoDB
    image: req.body.image
  };
  db.getClient()
    .db("shop")
    .collection("products")
    .updateOne({_id: new ObjectId(req.params.id)}, {$set: updatedProduct })
    .then(
      (mongoDbRes) => {
        console.log(mongoDbRes);
        res.status(201).json({ message: 'Product updated' });
      }
    )
    .catch(
      (err) => {
        console.log(err);
        res.status(500).json({ message: 'An error occurred when updating the product in the database.' });
      }
    );
});

// Delete a product
// Requires logged in user
router.delete('/:id', (req, res, next) => {
  db.getClient()
    .db("shop")
    .collection("products")
    .deleteOne({_id: new ObjectId(req.params.id)})
    .then(
      (mongoDbRes) => {
        console.log(mongoDbRes);
        res.status(200).json({ message: 'Product deleted' });
      }
    )
    .catch(
      (err) => {
        console.log(err);
        res.status(500).json({ message: 'An error occured when deleting the product.' });
      }
    );
});

module.exports = router;
