const fs   = require('fs');
const path = require('path');

/**
 * The model is responsible of the data access and management
 * In this app, the data are products, stored in a file
 * The model exposes methods to fetch all products, and save a new one.
 */


// path of the file on the server that stores all products
const filePath = path.join(path.dirname(require.main.filename), 'data', 'products.json');


// helper function to retrieve products fro mthe file and perform a callback on them
const getProductFromFile = (callbackFn) => {
    fs.readFile(filePath, (err, fileContent) => {
        let products = [];
        if (!err) {
            products = JSON.parse(fileContent);
        }
        callbackFn(products);
    });
};


// A model can be defined as an exported class representing an entity of our app logic
module.exports = class Product {

    // here to simplify the code we only get the title from the request
    // we could obviously get the price and the image URL in the same way
    constructor(title) {
        this.title = title;
        this.price = '20.00$';
        this.imageUrl = "https://developers.elementor.com/docs/assets/img/elementor-placeholder-image.png";
    }

    save() {
        getProductFromFile((products) => {
            products.push(this);
            // overwrite the products file with the new products array
            fs.writeFile(filePath, JSON.stringify(products), (err) => {
                console.log(err);
            });
        });
    }

    static fetchAllProducts(callbackFn) {
        getProductFromFile(callbackFn);
   }
}