const express = require('express');

const productsController = require('../controllers/products');

const router = express.Router();


// register a middleware for request GET /
router.get('/', productsController.getProducts);

module.exports = router;