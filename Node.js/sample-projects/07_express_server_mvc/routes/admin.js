const express = require('express');

const productsController = require('../controllers/products');

const router = express.Router();

// With the MVC pattern, the routes file no longer contains the logic.
// Instead it references the controller function in charge of handling that request


// register a middleware that returns a form for request GET /admin/add
// when submitting, it generates a POST request to url "/admin/message"
router.get('/add', productsController.getAddProduct);

// register a middleware to receive the POST request when the form is submitted
router.post('/message', productsController.postAddProduct);

module.exports = router;