const { ObjectId } = require('mongodb');
const mongo = require('../database');

/**
 * JS class accessing the MongoDB "products" collection
 */

class Product {
    constructor(title, price, imageUrl, description, userId, id) {
        this.title = title;
        this.price = price;
        this.imageUrl = imageUrl;
        this.description = description;
        this.userId = userId;
        // new products have no _id field, MongoDB will assign one for them
        if (id) {
            this._id = new ObjectId(id);
        }
    }

    save() {
        const db = mongo.getDb();
        if (this.hasOwnProperty("_id")) {
            // update existing product
            return db.collection('products').replaceOne({ _id: this._id }, this);
        } else {
            // create new product
            return db.collection('products').insertOne(this);
        }
    }

    static getAllProducts() {
        const db = mongo.getDb();
        return db.collection('products').find({}).toArray();
    }

    static getById(productId) {
        const db = mongo.getDb();
        return db.collection('products').findOne({ _id: new ObjectId(productId) });
    }

    static deleteById(productId) {
        const db = mongo.getDb();
        return db.collection('products').deleteOne({ _id: new ObjectId(productId) });
    }
}

module.exports = Product;
