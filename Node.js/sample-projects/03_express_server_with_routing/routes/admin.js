const express = require('express');

// use the Express router
const router = express.Router();

// register a middleware that returns a form for request GET /admin/add
// when submitting, it generates a POST request to url "/admin/message"
router.get('/add', (req, res, next) => {
    const htmlResponse = 
        '<html>'
        + '  <head><title>Enter Message</title></head>'
        + '  <body>'
        + '    <form action="/admin/message" method="POST">'
        + '      <input type="text" name="mess"/>'
        + '      <button type="submit">Send</button>'
        + '    </form>'
        + '  </body>'
        + '</html>';
    res.send(htmlResponse);
});

// register a middleware to receive the POST request when the form is submitted
router.post('/message', (req, res, next) => {
    res.send({message: req.body.mess});
});

module.exports = router;