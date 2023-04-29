const mongoose = require('mongoose');

/**
 * Mongoose model for the "product" collection
 * We define a schema and create a Mongoose model from this schema.
 * The schema can define custom methds that become available to instances of that model.
 * 
 * Compared to the previous implementation, we added the resetToken and resetTokenExpiration fields.
 * They are used when the user requests a password reset.
 * A temporary token is stored in the user object, to confirm that the the password change request
 * is initiated from the owner of the email.
 */

// we can define a schema for our collection, to let Mongoose know what
// objects in the collection will look like
// The schema does not mention the _id field, that is automatically added.
const userSchema = new mongoose.Schema({
    email: { type: String, required: true },
    password: { type: String, required: true },
    cart: { items: [{
        product: {type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true},
        quantity: {type: Number, required: true}
    }]},
    // the reset token and its expiration date are only present if a password reset is requested
    resetToken: { type: String, required: false },
    resetTokenExpiration: { type: Date, required: false }
});

// Custom methods 

userSchema.methods.addToCart = function(productId) {
    // mongoDB ObjectId objects must be compared as string (otherwise it returns false)
    const productIndex = this.cart.items.findIndex(p => p.product._id.toString() === productId);
    if (productIndex == -1) {
        // the product is not in the cart yet, add it
        this.cart.items.push({ product: productId, quantity: 1 });
    } else {
        // the product is already in the cat, increment its quantity
        this.cart.items[productIndex].quantity += 1;
    }
    return this.save();    
};

userSchema.methods.deleteFromCart = function(productId) {
    // mongoDB ObjectId objects must be compared as string (otherwise it returns false)
    const productIndex = this.cart.items.findIndex(p => p.product._id.toString() === productId);
    if (productIndex == -1) {
        // the product is not in the cart, cannot delete it
        console.log('WARNING - The product to delete is not in the cart.');
    } else {
        // remove the product from the cart
        this.cart.items.splice(productIndex, 1);
    }
    return this.save();    
};

userSchema.methods.clearCart = function() {
    this.cart.items = [];
    return this.save();
};

module.exports = mongoose.model('User', userSchema);
