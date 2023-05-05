const fs          = require('fs');
const path        = require('path');
const PDFdocument = require('pdfkit');
const { validationResult } = require('express-validator');

const utils = require('../utils.js');


// import the models
const Order = require('../models/order');
const Product = require('../models/product');
const User = require('../models/user');

const ITEM_PER_PAGE = 8;

/*
 * The controller exports the middleware functions it exposes, so they can be called from the routes files.
 * It uses the model to interact with data.
 * In this project, we use Mongoose models that each handles a MongoDB collection.
 */


exports.getProducts = (req, res, next) => {
    const page = Number(req.query.page) || 1;
    let productCount = 0;

    Product.find()
      .count()
      .then(count => {
        productCount = count;
        return Product.find()
          // skip up to the current page
          .skip((page-1) * ITEM_PER_PAGE)
          // only keep items of the current page
          .limit(ITEM_PER_PAGE);
      })
      .then((products) => {
        // render the view dynamically with the products
        res.render('products', {
          pageTitle: 'Products',
          products: products,
          currentPage: page,
          lastPage: Math.ceil(productCount / ITEM_PER_PAGE)
        });
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
  const page = Number(req.query.page) || 1;
  let productCount = 0;

  Product.find()
    .count()
    .then(count => {
      productCount = count;
      return Product.find()
        // skip up to the current page
        .skip((page-1) * ITEM_PER_PAGE)
        // only keep items of the current page
        .limit(ITEM_PER_PAGE);
    })
    .then((products) => {
      // render the view dynamically with the products
      res.render('products-admin', {
        pageTitle: 'Admin Products',
        products: products,
        currentPage: page,
        lastPage: Math.ceil(productCount / ITEM_PER_PAGE)
      });
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
  const description = req.body.description;

  // validate image uploaded by multer
  const image = req.file;
  if (!image) {
    // multer failed to upload the image
    return res.status(422).render('edit-product', {
      pageTitle: 'Add Product',
      action: 'add',
      // keep the previous user input so it does not get lost on reload
      product: { title: title, price: price, description: description },
      errorMessage: 'Attached file is not a valid image.',
      validationErrors: []
    });
  }
  // we store in DB the path of the uploaded image in the file system
  const imageUrl = image.path;

  // retrieve fields validation results from the validation middlewares
  const validationErrors = validationResult(req);
  if (!validationErrors.isEmpty()) {
    // 422 : Validation failed status
    utils.deleteFile(imageUrl);
    return res.status(422).render('edit-product', {
      pageTitle: 'Add Product',
      action: 'add',
      // keep the previous user input so it does not get lost on reload
      product: { title: title, price: price, description: description },
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
  const description = req.body.description;
  const productId = req.body.productId;
  const image = req.file;

  // retrieve fields validation results from the validation middlewares
  const validationErrors = validationResult(req);
  if (!validationErrors.isEmpty()) {
    // 422 : Validation failed status
    if (image) {
      utils.deleteFile(image.path);
    }
    return res.status(422).render('edit-product', {
      pageTitle: 'Edit Product',
      action: 'edit',
      // keep the previous user input so it does not get lost on reload
      product: { _id: productId, title: title, price: price, description: description },
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
    product.description = description;
    if (image) {
      // delete the previous file from the server asynchronously
      utils.deleteFile(product.imageUrl);
      // if a new image was uploaded, update the image path in the DB
      product.imageUrl = image.path;
    }
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
    Product.findOne({ _id: productId, userId: req.user._id })
    .then((product) => {
      if (!product) {
        throw new Error("No product found with ID " + productId);
      }
      // asynchronously delete the image from the file system
      utils.deleteFile(product.imageUrl);
      // delete the product from the products collection
      return Product.deleteOne({ _id: productId, userId: req.user._id });
    })
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

exports.getInvoice = (req, res, next) => {
  const orderId = req.params.orderId;
  Order.findById(orderId)
  .then((order) => {
    if (!order) {
      console.log("WARNING - No order found with ID = " + orderId);
      return next(new Error("Could not get invoice"));
    }
    if (order.userId.toString() !== req.user._id.toString()) {
      console.log("WARNING - Order with ID = " + orderId + " does not belong to user " + order.userId.toString());
      return next(new Error("Could not get invoice"));
    }
    const invoiceName = 'invoice-' + orderId + '.pdf';
    const invoicePath = path.join('uploads', 'invoices', invoiceName);

    // // Code to send an existing invoice file in one time
    // // it could be used if we created on server side an invoice file at every order
    // fs.readFile(invoicePath, (err, data) => {
    //   if (err) {
    //     return next(err);
    //   }
    //   // indication to the browser about how to open the file
    //   //    attachment : the browser will open a "Save As" window
    //   //    inline : the browser will open the file in a new tab
    //   res.setHeader('Content-Disposition', 'attachment; filename="' + invoiceName + '"');
    //   res.setHeader('Content-Type', 'application/pdf');
    //   res.send(data);
    // });  

    // create a PDF file and pipe it to write it on server-side
    const pdfDoc = new PDFdocument();
    pdfDoc.pipe(fs.createWriteStream(invoicePath));

    // generate the PDF file content
    pdfDoc.fontSize(24).text("Order " + orderId, { underline: true });
    pdfDoc.fontSize(12).text("   ");
    let totalPrice = 0;
    order.products.forEach((item) => {
      totalPrice += item.quantity * item.product.price;
      pdfDoc.text(item.quantity + ' x $ ' + item.product.price.toFixed(2) + "   " + item.product.title);
    });
    pdfDoc.text("   ");
    pdfDoc.fontSize(16).text("Total :  $ " + totalPrice.toFixed(2));
    pdfDoc.end();
    
    // indication to the browser about how to open the file
    //    attachment : the browser will open a "Save As" window
    //    inline : the browser will open the file in a new tab
    res.setHeader('Content-Disposition', 'attachment; filename="' + invoiceName + '"');
    res.setHeader('Content-Type', 'application/pdf');

    // stream the file to the response, this avoids loading the entire file in memory on server side before strating the trnasmission
    const fileToStream = fs.createReadStream(invoicePath);
    fileToStream.pipe(res);
  })
  .catch((err) => {
    next(err);
  });
};
