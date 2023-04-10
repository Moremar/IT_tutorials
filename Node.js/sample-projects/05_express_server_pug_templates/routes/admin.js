const express = require('express');
const path = require('path');

const router = express.Router();

// register a middleware that returns a form for request GET /admin/add-product
// when submitting, it generates a POST /admin/add-product
router.get('/add-product', (req, res, next) => {
    // use a pug template without a layout
    // we could simplify it by using the layout like other templates
    res.render('add-product');
});

// register a middleware to receive the POST request when the form is submitted
router.post('/add-product', (req, res, next) => {
    res.send({title: req.body.mess});
});

module.exports = router;