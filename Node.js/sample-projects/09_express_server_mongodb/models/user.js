const { ObjectId } = require('mongodb');
const mongo = require('../database');

/**
 * JS class accessing the "users" MongoDB collection.
 * Since we have a 1-to-1 relation between a user and a cart, the cart is stored
 * inside the user collection.
 */

const User = class {

    constructor(name, email, cart, _id) {
        this.name = name;
        this.email = email;
        this.cart = cart ? cart : {items: []};
        if (_id) {
            this._id = _id;    
        }
    }

    save() {
        const db = mongo.getDb();
        return db.collection('users').updateOne(
            { 'email': this.email },     // use the email as the unique identifier
            { $set : this } ,
            { upsert: true }
        );
    }

    addProductToCart(productId) {
        // mongoDB ObjectId objects must be compared as string (otherwise it returns false)
        const productIndex = this.cart.items.findIndex(p => p.productId.toString() === productId);
        if (productIndex == -1) {
            // the product is not in the cart yet, add it
            this.cart.items.push({ productId: new ObjectId(productId), quantity: 1 });
        } else {
            // the product is already in the cat, increment its quantity
            this.cart.items[productIndex].quantity += 1;
        }
        return this.save();
    }


    getCart() {
        // need to enrich products in the cart with their name and price
        // also skip products if they no longer exist in the products collection
        let productIds = this.cart.items.map(p => p.productId);
        const db = mongo.getDb();
        return db.collection('products').find({ _id: {$in: productIds} })
        .toArray()
        .then((products) => {
            let enrichedCart = [];
            for (let product of products) {
                // we know that the product is in the cart, get its index
                const cartIndex = this.cart.items.findIndex(p => p.productId.toString() === product._id.toString());
                enrichedCart.push({
                    ... product,
                    quantity: this.cart.items[cartIndex].quantity
                });
            }
            return enrichedCart;
        })

    }


    deleteProductFromCart(productId) {
        // mongoDB ObjectId objects must be compared as string (otherwise it returns false)
        const productIndex = this.cart.items.findIndex(p => p.productId.toString() === productId);
        if (productIndex == -1) {
            console.log('WARNING - product ' + productId + ' was not in the cart');
        } else {
            this.cart.items.splice(productIndex, 1);
        }
        return this.save();
    }

    checkout() {
        if (this.cart.items.length === 0) {
            console.log('WARNING - No product to checkout');
            return Promise.resolve(null);
        }
        const db = mongo.getDb();
        return this.getCart()
        .then((cartItems) => {
            return db.collection('orders').insertOne({
                userId: this._id,
                orderDate: new Date(),
                products: cartItems
            })
        })
        .then((res) => {
            // empty the cart now that the order is placed
            console.log('Created an order');
            this.cart.items = [];
            return this.save();
        })
    }

    getOrders() {
        const db = mongo.getDb();
        return db.collection('orders').find({ 'userId': this._id }).toArray();
    }

    static getByEmail(email) {
        const db = mongo.getDb();
        return db.collection('users').findOne({ 'email': email })
        .then((user) => {
            if (user) {
                return new User(user.name, user.email, user.cart, user._id);
            } else {
                return null;
            }
        })
    }

    static getById(userId) {
        const db = mongo.getDb();
        return db.collection('users').findOne({ '_id': new ObjectId(userId) })
        .then((user) => {
            if (user) {
                return new User(user.name, user.email, user.cart, user._id);
            } else {
                return null;
            }
        })
    }
};

module.exports = User;
