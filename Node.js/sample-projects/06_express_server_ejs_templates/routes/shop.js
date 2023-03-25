const express = require('express');
const path = require('path');

const router = express.Router();

// hardcoded list of products passed to the EJS template
const allProducts = [
    { title: "Red T-Shirt", price: '15.50$', imageUrl: 'https://www.babyshop.com/images/978457/card_xlarge.jpg'},
    { title: "Computer", price: '899.99$', imageUrl: 'https://media.gamestop.com/i/gamestop/11208199/CYBERPOWERPC-Ryzen-5-5500-RTX3060-Gaming-Desktop-PC-GMA7200GS-'}
];

// register a middleware for request GET /
router.get('/', (req, res, next) => {
    // EJS template including the common navbar
    res.render('shop', { pageTitle: 'My Shop', products: allProducts });
});

module.exports = router;