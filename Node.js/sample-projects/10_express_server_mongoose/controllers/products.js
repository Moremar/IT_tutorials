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
        console.log(err);
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
        console.log(err);
      });
};

// return the same products as the non-admin getProducts controller,
// but the view offers admin options (edit / delete)
exports.getAdminProducts = (req, res, next) => {
    // get all products from the model
    Product.find()
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
    res.render('edit-product', {pageTitle: 'Add Product', action: 'add', product: { title: '', price: '', imageUrl: '', description: '' }});
};

exports.getEditProduct = (req, res, next) => {
    // use the same EJS template as add-product to display the same form
    // provide different actions, so the "save" button directs to a different URL
    const productId = req.params.productId;
    Product.findById(productId)
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
  const product = new Product({
    title: req.body.title,
    price: Number(req.body.price),
    imageUrl: req.body.imageUrl,
    description: req.body.description,
    userId: req.user
  });
  product.save()
    .then((created) => {
        console.log('Created product ' + created._id.toString() + ' in the DB.');
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
  const update = {
    title: req.body.title,
    price: Number(req.body.price),
    imageUrl: req.body.imageUrl,
    description: req.body.description
  };
  Product.findByIdAndUpdate(productId, update, {new: true} /* to return the updated product */)
  .then((updatedProduct) => {
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
    Product.findByIdAndDelete(productId)
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
    return req.user.addToCart(productId)
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
    return req.user.deleteFromCart(productId)
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
    res.render('cart', {
      pageTitle: 'My Cart',
      cartItems: cartItems,
      totalPrice: cartPrice
    });
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
    console.log(err);
  });
};

exports.getOrders = (req, res, next) => {
  Order.find({ userId: req.user._id })
  .then((orders) => {
    res.render('orders', { pageTitle: 'My Orders', orders : orders });
  })
  .catch((err) => {
    console.log('ERROR - Could not get orders');
    console.log(err);
  });
};
