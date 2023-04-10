const express = require('express');

const router = express.Router();

// register a middleware for GET /
// This is exact match, so it will not be called for GET /xxx
router.get('/', (req, res, next) => {
    res.send('<h1>Welcome to the site !</h1>'
    + '<a href="/admin/add-product">Add Product</a>');

});

module.exports = router;