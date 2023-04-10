// import the models
const Product = require('../models/product');
const Cart    = require('../models/cart');

/*
 * The controller exports the middleware functions it exposes, so they can be called from the routes files.
 * It delegates data manipulation to the models.
 */


exports.getProducts = (req, res, next) => {
    // get products from the model
    Product.fetchAllProducts((products) => {
        // render the view dynamically with the products
        res.render('products', { pageTitle: 'Products', products: products });
    });
};

exports.getProduct = (req, res, next) => {
    // get the product ID from the request URL
    const productId = req.params.productId;
    // get a single product from the model
    Product.fetchProduct(productId, (product) => {
        if (!product) {
            return res.render('not-found', { pageTitle: 'Not Found' });
        }
        // render the detailed view for this product
        res.render('product-details', { pageTitle: 'Product Details', product: product });
    });
};

// return the same products as the non-admin getProducts controller,
// but the view offers admin options (edit / delete)
exports.getAdminProducts = (req, res, next) => {
    // get products from the model
    Product.fetchAllProducts((products) => {
        // render the view with admin options
        res.render('products-admin', { pageTitle: 'Admin Products', products: products });
    });
};

exports.getAddProduct = (req, res, next) => {
    // use the product edition EJS template with an empty product (with ID equal to -1)
    res.render('edit-product', {pageTitle: 'Add Product', action: 'add', product: new Product(-1, '', '', '', '')});
};

exports.getEditProduct = (req, res, next) => {
    // use the same EJS template as add-product to display the same form
    // provide different actions, so the "save" button directs to a different URL
    const productId = req.params.productId;
    console.log('Editing product ' + productId);
    Product.fetchProduct(productId, (product) => {
        res.render('edit-product', {pageTitle: 'Edit Product', action: 'edit', product: product});
    });
};

exports.postAddProduct = (req, res, next) => {
    // extract the product info from the POST request
    // the product ID of -1 indicates a new product
    const product = new Product(-1, req.body.title, req.body.imageUrl, Number(req.body.price), req.body.description);
    // save the new product
    product.save();
    res.redirect('/admin/products');
};

exports.postEditProduct = (req, res, next) => {
    // extract the product info from the POST request
    const product = new Product(Number(req.body.id), req.body.title, req.body.imageUrl, Number(req.body.price), req.body.description);
    // save the updated product
    product.save();
    res.redirect('/admin/products');
};

exports.postDeleteProduct = (req, res, next) => {
    // extract the product ID from the POST request
    const productId = Number(req.body.productId);
    // delete the product from the products list and the cart
    Product.deleteById(productId);
    res.redirect('/admin/products');
};

exports.postToCart = (req, res, next) => {
    // get the product ID from the request URL
    const productId = Number(req.body.productId);
    console.log('Add product to cart : ' + productId);
    Product.fetchProduct(productId, (product) => {
        Cart.addProduct(productId, product.price);
        res.redirect('/products');
    });
};

exports.deleteFromCart = (req, res, next) => {
    // get the product ID from the request URL
    const productId = Number(req.body.productId);
    console.log('Delete product from cart : ' + productId);
    Product.fetchProduct(productId, (product) => {
        Cart.deleteProduct(productId, product.price);
        res.redirect('/cart');
    });
};

exports.getCart = (req, res, next) => {
    Cart.getCart((cart) => {
        Product.fetchAllProducts((products) => {
            const cartItems = [];
            for (let cartProduct of cart.products) {
                const productIndex = products.findIndex(p => p.id === cartProduct.productId);
                cartItems.push({ product: products[productIndex], quantity: cartProduct.quantity });
            }
            res.render('cart', { pageTitle: 'My Cart', cartItems: cartItems, totalPrice: cart.totalPrice });
        });
    });
};
