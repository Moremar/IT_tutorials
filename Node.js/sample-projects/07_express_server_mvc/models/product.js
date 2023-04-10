const { randomInt } = require('crypto');
const fs   = require('fs');
const path = require('path');
const Cart = require('./cart');

/**
 * The model is responsible of the data access and management
 * In this app, the data are products, stored in a file
 * The model exposes methods to fetch, create, edit or delete products.
 * 
 * The storage is entirely managed using a file per model (no database used here)
 */


// path of the file on the server that stores all products
const PRODUCT_FILE_PATH = path.join(path.dirname(require.main.filename), 'data', 'products.json');


// helper function to retrieve products from the file and perform a callback on them
const getProductFromFile = (callbackFn) => {
    fs.readFile(PRODUCT_FILE_PATH, (err, fileContent) => {
        let products = [];
        if (!err) {
            products = JSON.parse(fileContent);
        }
        callbackFn(products);
    });
};


// A model can be defined as an exported class representing an entity of our app logic
module.exports = class Product {

    constructor(id, title, imageUrl, price, description) {
        this.id = id;
        this.title = title;
        this.imageUrl = imageUrl;
        this.price = price;
        this.description = description;
    }

    save() {
        getProductFromFile((products) => {
            if (this.id === -1) {
                // create a new product and give it an ID
                this.id = randomInt(2000000000);   // in a real app, need a real unique ID generator
                products.push(this);
            } else {
                // update an existing product
                const productIndex = products.findIndex(p => p.id === this.id);
                products[productIndex] = this;
            }
            // overwrite the products file with the new products array
            fs.writeFile(PRODUCT_FILE_PATH, JSON.stringify(products), (err) => {
                if (err) {
                    console.log(err);
                }
            });
        });
    }

    static deleteById(productId) {
        getProductFromFile((products) => {
            const productIndex = products.findIndex(p => p.id === productId);
            if (productIndex !== -1) {
                const productPrice = products[productIndex].price;
                products.splice(productIndex, 1);
                // overwrite the products file with the new products array
                fs.writeFile(PRODUCT_FILE_PATH, JSON.stringify(products), (err) => {
                    if (err) {
                        console.log(err);
                        return;
                    }
                    // delete the product from the cart if it exists
                    Cart.deleteProduct(productId, productPrice);
                });
            }
        });
    }

    static fetchAllProducts(callbackFn) {
        getProductFromFile(callbackFn);
    }

    static fetchProduct(productId, callbackFn) {
        getProductFromFile((products) => {
            const filtered = products.filter(p => p.id == productId);
            const product = (filtered.length == 0)
                          ? null
                          : new Product(filtered[0].id, filtered[0].title, filtered[0].imageUrl, filtered[0].price, filtered[0].description);
            console.log("Fetched product with ID " + productId + " : " + product);
            callbackFn(product);
        });
    }
}