const express = require('express');

const productsController = require('../controllers/products');

const router = express.Router();

// register a controller middleware for each available route

// GET /admin/products
// display products with admin options (edit/delete)
router.get('/products', productsController.getAdminProducts);

// GET /admin/add-product
// display the form to add a new product
// when submitting, it generates a POST /admin/add-product
router.get('/add-product', productsController.getAddProduct);

// POST /admin/add-product
// handle the POST request on form submission
router.post('/add-product', productsController.postAddProduct);

// GET /admin/edit-product/<id>
// returns the HTML page with the edit form
// when submitting, it generates a POST /admin/edit-product
router.get('/edit-product/:productId', productsController.getEditProduct);

// POST /admin/edit-product
// handle the POST request on form submission
router.post('/edit-product', productsController.postEditProduct);

// POST /admin/delete-product
router.post('/delete-product', productsController.postDeleteProduct);

module.exports = router;