const express = require('express');

const productsController = require('../controllers/products');

const router = express.Router();

// register a middleware for each available route

// GET /
// redirects to the products page
router.get('/', (req, res, next) => { res.redirect('/products'); });

// GET /products
router.get('/products', productsController.getProducts);

// GET /product/<id>
// detailed product view
router.get('/product/:productId', productsController.getProduct);

// GET /cart
router.get('/cart', productsController.getCart);

// POST /cart
// add a product to the cart
router.post('/cart', productsController.postToCart);

// POST /cart/delete
// delete a product from the cart
router.post('/cart/delete', productsController.deleteFromCart);

// POST /cart/checkout
// create an order with all products in the cart and empty the cart
router.post('/cart/checkout', productsController.checkout);

// GET /orders
router.get('/orders', productsController.getOrders);

module.exports = router;