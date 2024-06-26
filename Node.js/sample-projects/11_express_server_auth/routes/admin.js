const express = require('express');
const { body } = require('express-validator');

const productsController = require('../controllers/products');
const isAuth = require("../middlewares/is-auth");

const router = express.Router();

// register a controller middleware for each available route

// GET /admin/products
// display products with admin options (edit/delete)
router.get('/products', isAuth, productsController.getAdminProducts);

// GET /admin/add-product
// display the form to add a new product
// when submitting, it generates a POST /admin/add-product
router.get('/add-product', isAuth, productsController.getAddProduct);

// POST /admin/add-product
// handle the POST request on form submission
router.post('/add-product',
    isAuth,
    body('title', 'Invalid product title')
        .trim()
        .isLength({min: 3, max: 30}),
    body('price', 'Invalid product price')
        .isFloat({min: 0}),
    body('description', 'Invalid product description')
        .trim()
        .isLength({min: 5, max: 200}),
    productsController.postAddProduct);

// GET /admin/edit-product/<id>
// returns the HTML page with the edit form
// when submitting, it generates a POST /admin/edit-product
router.get('/edit-product/:productId', isAuth, productsController.getEditProduct);

// POST /admin/edit-product
// handle the POST request on form submission
router.post('/edit-product',
    isAuth,
    body('title', 'Invalid product title')
        .trim()
        .isLength({min: 3, max: 30}),
    body('price', 'Invalid product price')
        .isFloat({min: 0}),
    body('description', 'Invalid product description')
        .trim()
        .isLength({min: 5, max: 200}),
    productsController.postEditProduct);

// DELETE /admin/product/:productId
router.delete('/product/:productId', isAuth, productsController.deleteProduct);

module.exports = router;