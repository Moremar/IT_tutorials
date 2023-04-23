const mongoose = require('mongoose');

/**
 * Mongoose model for the "orders" collection
 */

// we can define a schema for our collection, to let Mongoose know what
// objects in the collection will look like
// The schema does not mention the _id field, that is automatically added.
const orderSchema = new mongoose.Schema({
    orderDate: { type: String, required: true },
    userId: {type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true},
    products:  [{
        // store the full product, as we want to keep the version at order time
        product: {type: Object, required: true},
        quantity: {type: Number, required: true}
    }]
});

module.exports = mongoose.model('Order', orderSchema);
