const express = require('express');
const path = require('path');

const router = express.Router();

// register a middleware that returns a form for request GET /admin/add
// when submitting, it generates a POST request to url "/admin/message"
router.get('/add-product', (req, res, next) => {
    // use an EJS template
    res.render('add-product', {pageTitle: 'Add Product'});
});

// register a middleware to receive the POST request when the form is submitted
router.post('/add-product', (req, res, next) => {
    res.send({title: req.body.mess});
});

module.exports = router;