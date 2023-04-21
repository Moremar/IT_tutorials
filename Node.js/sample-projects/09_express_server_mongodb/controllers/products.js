// import the models
const Product = require('../models/product');
const User = require('../models/user');

/*
 * The controller exports the middleware functions it exposes, so they can be called from the routes files.
 * It uses the model to interact with data.
 * In this project, the models are custom classes that expose actions to interact with the MongoDB database.
 */


exports.getProducts = (req, res, next) => {
    // get all products from the model
    Product.getAllProducts()
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
    Product.getById(productId)
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
    // get all products from the model
    Product.getAllProducts()
      .then((products) => {
        // render the view dynamically with the products
        res.render('products-admin', { pageTitle: 'Admin Products', products: products });        
      })
      .catch((err) => {
        console.log('ERROR - Could not fetch products from the DB');
        console.log(err);
      });    
};

exports.getAddProduct = (req, res, next) => {
    // use the product edition EJS template with an empty product
    res.render('edit-product', {pageTitle: 'Add Product', action: 'add', product: new Product('', '', '', '', '')});
};

exports.getEditProduct = (req, res, next) => {
    // use the same EJS template as add-product to display the same form
    // provide different actions, so the "save" button directs to a different URL
    const productId = req.params.productId;
    Product.getById(productId)
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
  const product = new Product(
        req.body.title,
        Number(req.body.price),
        req.body.imageUrl,
        req.body.description,
        req.userId);
  product.save()
    .then((created) => {
        console.log('Created product ' + created.insertedId.toString() + ' in the DB.');
        res.redirect('/admin/products');
    })
    .catch((err) => {
        console.log('ERROR - Could not create new product');
        console.log(err);
    });
};

exports.postEditProduct = (req, res, next) => {
  // retrieve the product to get its userId
  const productId = req.body.productId;
  Product.getById(productId)
  .then((product) => {
    // build a product model instance that can be saved
    const updatedProduct = new Product(
      req.body.title,
      Number(req.body.price),
      req.body.imageUrl,
      req.body.description,
      product.userId,
      product._id
    );
    return updatedProduct.save();
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
    const productId = req.body.productId;
    // delete the product from the products list
    Product.deleteById(productId)
      .then(() => {
        console.log('Deleted product ' + productId + ' from the DB.');
        res.redirect('/admin/products'); 
      })
      .catch((err) => {
        console.log('ERROR - Could not delete product ' + productId);
        console.log(err);
      });
};

exports.postToCart = (req, res, next) => {
    // get the product ID from the request URL
    const productId = req.body.productId;
    User.getById(req.userId)
    .then((user) => {
      return user.addProductToCart(productId);
    })
    .then(() => {
      console.log('Added product ' + productId + ' to the cart');
      res.redirect('/cart');
    })
    .catch((err) => {
      console.log('ERROR - Could not add product ' + productId + ' to the cart');
      console.log(err);
    });
};

exports.deleteFromCart = (req, res, next) => {
    // get the product ID from the request URL
    const productId = req.body.productId;
    return User.getById(req.userId)
    .then((user) => {
      return user.deleteProductFromCart(productId);
    })
    .then(() => {
      console.log('Deleted product ' + productId + ' from the cart');
      res.redirect('/cart');
    })
    .catch((err) => {
      console.log('ERROR - Could not delete product ' + productId + ' from the cart');
      console.log(err);
    });
};

exports.getCart = (req, res, next) => {
  User.getById(req.userId)
  .then((user) => {
    return user.getCart();
  })
  .then((cartItems) => {
    let cartPrice = 0;
    for (let product of cartItems) {
      cartPrice += product.price * product.quantity;
    }
    res.render('cart', {
      pageTitle: 'My Cart',
      products: cartItems,
      totalPrice: cartPrice
    });
  })
};

exports.checkout = (req, res, next) => {
  User.getById(req.userId)
  .then((user) => {
    return user.checkout();
  })
  .then(() => {
    console.log('Order all products from the cart');
    res.redirect('/orders');
  })
  .catch((err) => {
    console.log('ERROR - Could not checkout products from the cart');
    console.log(err);
  });
};

exports.getOrders = (req, res, next) => {
  User.getById(req.userId)
  .then((user) => {
    return user.getOrders();
  })
  .then((orders) => {
    res.render('orders', { pageTitle: 'My Orders', orders : orders });
  })
  .catch((err) => {
    console.log('ERROR - Could not get orders');
    console.log(err);
  });
};
