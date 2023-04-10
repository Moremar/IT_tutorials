const express = require('express');

// use the Express router
const router = express.Router();

// register a middleware that returns a form for request GET /admin/add-product
// when submitting, it generates a POST /admin/add-product
router.get('/add-product', (req, res, next) => {
    const htmlResponse = 
        '<html>'
        + '  <head><title>Add Product</title></head>'
        + '  <body>'
        + '    <form action="/admin/add-product" method="POST">'
        + '      <input type="text" name="mess"/>'
        + '      <button type="submit">Send</button>'
        + '    </form>'
        + '  </body>'
        + '</html>';
    res.send(htmlResponse);
});

// register a middleware to receive the POST request when the form is submitted
router.post('/add-product', (req, res, next) => {
    res.send({title: req.body.mess});
});

module.exports = router;