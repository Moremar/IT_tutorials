const { validationResult } = require('express-validator');

// import the models
const Order = require('../models/order');
const Product = require('../models/product');
const User = require('../models/user');

/*
 * The controller exports the middleware functions it exposes, so they can be called from the routes files.
 * It uses the model to interact with data.
 * In this project, we use Mongoose models that each handles a MongoDB collection.
 */


exports.getProducts = (req, res, next) => {
    // get all products from the model
    Product.find()
      .then((products) => {
        // render the view dynamically with the products
        res.render('products', { pageTitle: 'Products', products: products });
      })
      .catch((err) => {
        console.log('ERROR - Could not fetch products from the DB');
        next(err);
      });
};


exports.getProduct = (req, res, next) => {
    // get the product ID from the request URL
    const productId = req.params.productId;
    // get a single product from the model
    Product.findById(productId)
      .then((product) => {
        if (!product) {
            return res.render('not-found', { pageTitle: 'Not Found' });
        }
        // render the detailed view for this product
        res.render('product-details', { pageTitle: 'Product Details', product: product });
      })
      .catch((err) => {
        console.log('ERROR - Could not fetch product ' + productId + ' from the DB');
        next(err);
      });
};

// return all the products owned by the currently authenticated user, with admin options (edit/delete)
exports.getAdminProducts = (req, res, next) => {
    // get all products from the model that belong to the currently authenticated user
    Product.find({ userId: req.user._id })
      .then((products) => {
        // render the view dynamically with the products
        res.render('products-admin', { pageTitle: 'Admin Products', products: products });
      })
      .catch((err) => {
        console.log('ERROR - Could not fetch products from the DB');
        next(err);
      });    
};


exports.getAddProduct = (req, res, next) => {
    // use the product edition EJS template with an empty product
    res.render('edit-product', {
      pageTitle: 'Add Product',
      action: 'add',
      product: { title: '', price: '', imageUrl: '', description: '' },
      errorMessage: '',
      validationErrors: []
    });
};


exports.getEditProduct = (req, res, next) => {
    // use the same EJS template as add-product to display the same form
    // provide different actions, so the "save" button directs to a different URL
    const productId = req.params.productId;
    Product.findById(productId)
      .then((product) => {
        if (!product || product.userId.toString() != req.user._id.toString()) {
            return res.render('not-found', {
              pageTitle: 'Not Found'
            });
        }
        // render the edit form for this product
        res.render('edit-product', {
          pageTitle: 'Edit Product',
          action: 'edit',
          product: product,
          errorMessage: '',
          validationErrors: []
        });
      })
      .catch((err) => {
        console.log('ERROR - Could not fetch product ' + productId + ' from the DB');
        next(err);
      });
};


exports.postAddProduct = (req, res, next) => {
  const title = req.body.title;
  const price = Number(req.body.price);
  const imageUrl = req.body.imageUrl;
  const description = req.body.description;

  // retrieve fields validation results from the validation middlewares
  const validationErrors = validationResult(req);
  if (!validationErrors.isEmpty()) {
    // 422 : Validation failed status
    return res.status(422).render('edit-product', {
      pageTitle: 'Add Product',
      action: 'add',
      // keep the previous user input so it does not get lost on reload
      product: { title: title, imageUrl: imageUrl, price: price, description: description },
      errorMessage: validationErrors.array()[0].msg,
      validationErrors: validationErrors.array()    // used for red borders on error fields in the view
    });
  }
  // save the new product
  const product = new Product({
    title: title,
    price: price,
    imageUrl: imageUrl,
    description: description,
    userId: req.user
  });
  product.save()
    .then((created) => {
        console.log('Created product ' + created._id.toString() + ' in the DB.');
        res.redirect('/admin/products');
    })
    .catch((err) => {
        console.log('ERROR - Could not create new product');
        next(err);
    });
};


exports.postEditProduct = (req, res, next) => {
  const title = req.body.title;
  const price = Number(req.body.price);
  const imageUrl = req.body.imageUrl;
  const description = req.body.description;
  const productId = req.body.productId;

  // retrieve fields validation results from the validation middlewares
  const validationErrors = validationResult(req);
  if (!validationErrors.isEmpty()) {
    // 422 : Validation failed status
    return res.status(422).render('edit-product', {
      pageTitle: 'Edit Product',
      action: 'edit',
      // keep the previous user input so it does not get lost on reload
      product: { _id: productId, title: title, imageUrl: imageUrl, price: price, description: description },
      errorMessage: validationErrors.array()[0].msg,
      validationErrors: validationErrors.array()    // used for red borders on error fields in the view
    });
  }

  Product.findById(productId)
  .then((product) => {
    // do not edit if the product does not exist or belongs to another user
    if (!product || product.userId.toString() != req.user._id.toString()) {
      return res.render('not-found', {
        pageTitle: 'Not Found'
      });
    }
    product.title = title;
    product.price = price;
    product.imageUrl = imageUrl;
    product.description = description;
    return product.save()
    .then(() => {
      console.log('Updated product ' + productId + ' in the DB.');
      res.redirect('/admin/products');
    })
  })
  .catch((err) => {
    console.log('ERROR - Could not update product');
    next(err);
  });
};


exports.postDeleteProduct = (req, res, next) => {
    // get the product ID from the request URL
    const productId = req.body.productId;
    // delete the product from the products list
    Product.deleteOne({ _id: productId, userId: req.user._id })
      .then(() => {
        console.log('Deleted product ' + productId + ' from the DB.');
        res.redirect('/admin/products'); 
      })
      .catch((err) => {
        console.log('ERROR - Could not delete product ' + productId);
        next(err);
      });
};


exports.postToCart = (req, res, next) => {
    // get the product ID from the request URL
    const productId = req.body.productId;
    return req.user.addToCart(productId)
    .then(() => {
      console.log('Added product ' + productId + ' to the cart');
      res.redirect('/cart');
    })
    .catch((err) => {
      console.log('ERROR - Could not add product ' + productId + ' to the cart');
      next(err);
    });
};


exports.deleteFromCart = (req, res, next) => {
    // get the product ID from the request URL
    const productId = req.body.productId;
    return req.user.deleteFromCart(productId)
    .then(() => {
      console.log('Deleted product ' + productId + ' from the cart');
      res.redirect('/cart');
    })
    .catch((err) => {
      console.log('ERROR - Could not delete product ' + productId + ' from the cart');
      next(err);
    });
};


exports.getCart = (req, res, next) => {
  // we already have the user in req.user, but we cann the model to get a promise and
  // chain with populate() to get Mongoose to retrieve the underlying products
  User.findOne({ _id: req.user._id })
  // replace the productId by the actual product
  .populate("cart.items.product")
  .then((user) => {
    let cartPrice = 0;
    let cartItems = [];
    for (let item of user.cart.items) {
      // skip products from the cart that have been deleted (populate() will return null for them)
      if (item.product) {
        cartPrice += item.product.price * item.quantity;
        cartItems.push(item);
      }
    }
    res.render('cart', { pageTitle: 'My Cart', cartItems: cartItems, totalPrice: cartPrice });
  });
};


exports.checkout = (req, res, next) => {
  // we already have the user in req.user, but we cann the model to get a promise and
  // chain with populate() to get Mongoose to retrieve the underlying products
  User.findOne({ _id: req.user._id })
  // replace the productId by the actual product
  .populate("cart.items.product")
  .then((user) => {
    const orderProducts = user.cart.items
        .filter(p => p.product != null)
        // we use the "_doc" field of the document so we get the actual JS document
        // for the product field and not just the product ID that Mongoose uses by default
        // when saving the order
        .map(p => { return { product: { ... p.product._doc }, quantity: p.quantity }; });

    const order = new Order({
      orderDate: new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'numeric', year: 'numeric' }),
      userId: req.user._id,
      products: orderProducts
    });
    return order.save();
  })
  .then(() => {
    // empty the cart once the order is saved
    return req.user.clearCart();
  })
  .then(() => {
    console.log('Ordered all products from the cart');
    res.redirect('/orders');
  })
  .catch((err) => {
    console.log('ERROR - Could not checkout products from the cart');
    next(err);
  });
};


exports.getOrders = (req, res, next) => {
  Order.find({ userId: req.user._id })
  .then((orders) => {
    res.render('orders', { pageTitle: 'My Orders', orders : orders });
  })
  .catch((err) => {
    console.log('ERROR - Could not get orders');
    next(err);
  });
};
