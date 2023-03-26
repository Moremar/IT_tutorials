// import the product model
const Product = require('../models/product');

/*
 * The controller exports the functions it exposes, so they can be called from the routes files.
 * It delegates data manipulation to the models.
 */


exports.getProducts = (req, res, next) => {
    // get products from the model
    Product.fetchAllProducts((products) => {
        // render the view dynamically with the products
        res.render('shop', { pageTitle: 'My Shop', products: products });
    });
};

exports.getAddProduct = (req, res, next) => {
    // use an EJS template
    res.render('add-product');
};

exports.postAddProduct = (req, res, next) => {
    const product = new Product(req.body.mess);
    product.save();
    res.redirect('/');
};


