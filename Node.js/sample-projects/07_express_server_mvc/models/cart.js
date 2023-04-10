const fs   = require('fs');
const path = require('path');

/**
 * Model to interact with the cart data.
 * The app only handles a single cart so no need to have an instanciable class here.
 * Instead, this class provides static methods to get, add objects or delete objects from the cart.
 * 
 * The cart is stored as a JSON file on the server (no database used here)
 */

// path of the file on the server that stores the cart
const CART_FILE_PATH = path.join(path.dirname(require.main.filename), 'data', 'cart.json');


// A model can be defined as an exported class representing an entity of our app logic
module.exports = class Cart {

    static addProduct(productId, price) {
        fs.readFile(CART_FILE_PATH, (err, fileContent) => {
            let cart = { products: [], totalPrice: 0 };
            if (!err) {
                // the cart file exists, retrieve it
                cart = JSON.parse(fileContent);
            }
            // add new product or increase quantity if existing            
            const existingProductIndex = cart.products.findIndex(p => p.productId == productId);
            if (existingProductIndex != -1) {
                cart.products[existingProductIndex].quantity = cart.products[existingProductIndex].quantity + 1;
            } else {
                cart.products.push({productId: productId, quantity : 1});
            }
            cart.totalPrice = Number(cart.totalPrice) + price;

            console.log(cart);

            // save the cart back to file
            fs.writeFile(CART_FILE_PATH, JSON.stringify(cart), (err) => {
                if (err) {
                    console.log('An error occured when writing the cart file :');
                    console.log(err);
                }
            });
        });
    }

    static deleteProduct(productId, productPrice) {
        fs.readFile(CART_FILE_PATH, (err, fileContent) => {
            let cart = { products: [], totalPrice: 0 };
            if (err) {
                // no cart file, so no product to
                return;
            }
            cart = JSON.parse(fileContent);
            // add new product or increase quantity if existing            
            const existingProductIndex = cart.products.findIndex(p => p.productId == productId);
            if (existingProductIndex == -1) {
                // the product to delete is not in the cart
                return;
            }
            // remove the product and adjust the cart total price
            cart.totalPrice -= cart.products[existingProductIndex].quantity * productPrice;
            cart.products.splice(existingProductIndex, 1);

            console.log(cart);

            // save the cart back to file
            fs.writeFile(CART_FILE_PATH, JSON.stringify(cart), (err) => {
                if (err) {
                    console.log('An error occured when writing the cart file :');
                    console.log(err);
                }
            });
        });
    }

    static getCart(callbackFn) {
        fs.readFile(CART_FILE_PATH, (err, fileContent) => {
            let cart = { products: [], totalPrice: 0 };
            if (!err) {
                // the cart file exists, retrieve it
                cart = JSON.parse(fileContent);
            }
            callbackFn(cart);
        });
    }

}