// import the models
const Product = require('../models/product');

/*
 * The controller exports the middleware functions it exposes, so they can be called from the routes files.
 * It uses the model to interact with data.
 * In this project, the models are Sequelize models, so they are used to create/update/delete objects from the DB
 */


exports.getProducts = (req, res, next) => {
    // get all products from the model
    Product.findAll()
      .then((products) => {
        // render the view dynamically with the products
        res.render('products', { pageTitle: 'Products', products: products });        
      })
      .catch((err) => {
        console.log('ERROR - Could not fetch products from the DB');
        console.log(err);
      });
};


exports.getProduct = (req, res, next) => {
    // get the product ID from the request URL
    const productId = req.params.productId;
    // get a single product from the model
    Product.findByPk(productId)
      .then((product) => {
        if (!product) {
            return res.render('not-found', { pageTitle: 'Not Found' });
        }
        // render the detailed view for this product
        res.render('product-details', { pageTitle: 'Product Details', product: product });
      })
      .catch((err) => {
        console.log('ERROR - Could not fetch product ' + productId + ' from the DB');
        console.log(err);
      });
};

// return the same products as the non-admin getProducts controller,
// but the view offers admin options (edit / delete)
exports.getAdminProducts = (req, res, next) => {
    // get products from the model
    // here we do not user Product.findAll(), to limit only the results to
    // products that belong to the user (we could use a where clause in findAll)
    // (this does not make any difference in this app since we have a single user)
    req.user.getProducts()
    .then((products) => {
      // render the view with admin options
      res.render('products-admin', { pageTitle: 'Admin Products', products: products });        
    })
    .catch((err) => {
      console.log('ERROR - Could not fetch products from the DB');
      console.log(err);
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
    Product.findByPk(productId)
      .then((product) => {
        if (!product) {
            return res.render('not-found', { pageTitle: 'Not Found' });
        }
        // render the edit form for this product
        res.render('edit-product', { pageTitle: 'Edit Product', action: 'edit', product: product });
      })
      .catch((err) => {
        console.log('ERROR - Could not fetch product ' + productId + ' from the DB');
        console.log(err);
      });
};

exports.postAddProduct = (req, res, next) => {
    // extract the product info from the POST request
    req.user.createProduct({
        title: req.body.title,
        imageUrl: req.body.imageUrl,
        price: Number(req.body.price),
        description: req.body.description
    })
    .then((product) => {
        console.log('Created product ' + product.id + ' in the DB.');
        res.redirect('/admin/products');
    })
    .catch((err) => {
        console.log('ERROR - Could not create new product');
        console.log(err);
    });
};

exports.postEditProduct = (req, res, next) => {
    // extract the product info from the POST request
    const productId = Number(req.body.id);
    req.user.getProducts({where: { id: productId }})
      .then((products) => {
        if (products.length > 0) {
            return products[0].update({
                title: req.body.title,
                imageUrl: req.body.imageUrl,
                price: Number(req.body.price),
                description: req.body.description
            });
        }
      })
      .then(() => {
        console.log('Updated product ' + productId + ' in the DB.');
        res.redirect('/admin/products');
      })
      .catch((err) => {
        console.log('ERROR - Could not update product');
        console.log(err);
    });
};

exports.postDeleteProduct = (req, res, next) => {
    // get the product ID from the request URL
    const productId = Number(req.body.productId);
    // delete the product from the products list
    Product.destroy({where: { id: productId }})
      .then((id) => {
        console.log('Deleted product ' + id + ' from the DB.');
        res.redirect('/admin/products'); 
      })
      .catch((err) => {
        console.log('ERROR - Could not delete product ' + productId);
        console.log(err);
      });
};

exports.postToCart = (req, res, next) => {
    // get the product ID from the request URL
    const productId = Number(req.body.productId);
    console.log('Add product to cart : ' + productId);
    let currCart;
    req.user.getCart()
      // need to check if the product is already in the cart
      .then((cart) => {
        currCart = cart;
        return cart.getProducts({where: {id: productId}});
      })
      .then((products) => {
        if (products.length > 0) {
            // if the product is already in the cart, increase its quantity
            const product = products[0];
            const newQuantity = product.cartItem.quantity + 1;
            return currCart.addProduct(product, { through: { quantity: newQuantity}});
        } else {
            // otherwise, find the product and add it to the cart
            return Product.findByPk(productId)
              .then((currProduct) => {
                return currCart.addProduct(currProduct, { through: { quantity: 1}});
              })
              .catch((err)=> {
                console.log('ERROR - Could not retrieve product ' + productId);
                console.log(err);
              });
        }
      })
      .then(() => {
        res.redirect('/cart');
      })
      .catch((err) => {
        console.log('ERROR - Could not add product ' + productId + ' to the cart');
        console.log(err);
      });
};

exports.deleteFromCart = (req, res, next) => {
    // get the product ID from the request URL
    const productId = Number(req.body.productId);
    console.log('Delete product from cart : ' + productId);
    req.user.getCart()
      .then((cart) => {
        return cart.removeProduct(productId);
      })
      .then(() => {
        res.redirect('/cart');
      })
      .catch((err) => {
        console.log('ERROR - Could not delete product ' + productId + ' from the cart');
        console.log(err);
      });
};

exports.getCart = (req, res, next) => {
    req.user.getCart()
      .then((cart) => {
        // Sequelize associations let us get products from the Cart model
        return cart.getProducts();
      })
      .then((products) => {
        let cartPrice = 0;
        for (let product of products) {
            cartPrice += product.price * product.cartItem.quantity;
        }
        res.render('cart', { pageTitle: 'My Cart', products: products, totalPrice: cartPrice });
      })
      .catch((err) => {
        console.log('ERROR - Could not fetch the cart');
        console.log(err);
      });
};

exports.checkout = (req, res, next) => {
    let currCart;
    let currProducts;
    req.user.getCart()
      .then((cart) => {
        currCart = cart;
        return cart.getProducts();
      })
      .then((products) => {
        currProducts = products;
        return req.user.createOrder({orderDate: new Date()});
      })
      .then((order) => {
        // to create the orders, we need to give the products and the quantity to assign to each product
        productsWithQty = currProducts.map(p => {
            p.orderItem = { quantity: p.cartItem.quantity };
            return p;
        });
        return order.addProducts(productsWithQty);
      })
      .then(() => {
        // empty the cart
        currCart.setProducts(null);
      })
      .then(() => {
        res.redirect('/orders');
      })
      .catch((err) => {
        console.log('ERROR - Could not checkout products from the cart');
        console.log(err);
      });
};

exports.getOrders = (req, res, next) => {
    // by default, fetching all orders will not include the associated products for each order
    // we can force to include them in the response with the "include" option
    req.user.getOrders({include: ['products']})
      .then((orders) => {
        res.render('orders', { pageTitle: 'My Orders', orders : orders });
    })
      .catch((err) => {
        console.log('ERROR - Could not get orders');
        console.log(err);
      });
};
