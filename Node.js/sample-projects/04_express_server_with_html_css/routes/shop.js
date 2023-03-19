const express = require('express');
const path = require('path');

const router = express.Router();

// register a middleware for request GET /
router.get('/', (req, res, next) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'shop.html'));
});

module.exports = router;