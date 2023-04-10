const express = require('express');
const path = require('path');

const router = express.Router();

// GET /admin/add-product
// when submitting, it generates a POST /admin/add-product
router.get('/add-product', (req, res, next) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'add-product.html'));
});

// register a middleware to receive the POST request when the form is submitted
router.post('/add-product', (req, res, next) => {
    res.send({title: req.body.mess});
});

module.exports = router;