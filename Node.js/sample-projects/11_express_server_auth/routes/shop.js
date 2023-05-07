const express = require('express');

const productsController = require('../controllers/products');
const isAuth = require("../middlewares/is-auth");

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
router.get('/cart', isAuth, productsController.getCart);

// POST /cart
// add a product to the cart
router.post('/cart', isAuth, productsController.postToCart);

// POST /cart/delete
// delete a product from the cart
router.post('/cart/delete', isAuth, productsController.deleteFromCart);

// GET checkout
// show the page with the details of products about to be paid
// clicking PAY calls Stripe for the actual payment page
router.get("/checkout", isAuth, productsController.getCheckout);

// GET checkout/cancel
// redirected to this route when the payment with Stripe was cancelled
// we simply redirect to the checkout page
router.get("/checkout/cancel", isAuth, productsController.getCheckout);

// GET checkout/success
// redirected to this route when the payment with Stripe was successful
// create an order with all products in the cart and empty the cart
router.get("/checkout/success", isAuth, productsController.getCheckoutSuccess);

// GET /orders
router.get('/orders', isAuth, productsController.getOrders);

// GET /orders/:orderId
// create and download the invoice file for a specific order
router.get('/orders/:orderId', isAuth, productsController.getInvoice);

module.exports = router;