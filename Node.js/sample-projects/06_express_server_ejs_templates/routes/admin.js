const express = require('express');
const path = require('path');

const router = express.Router();

// register a middleware that returns a form for request GET /admin/add
// when submitting, it generates a POST request to url "/admin/message"
router.get('/add', (req, res, next) => {
    // use an EJS template
    res.render('add-product');
});

// register a middleware to receive the POST request when the form is submitted
router.post('/message', (req, res, next) => {
    res.send({message: req.body.mess});
});

module.exports = router;