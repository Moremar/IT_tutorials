const mongoose = require('mongoose');

/**
 * Mongoose model for the "product" collection
 * We define a schema and create a Mongoose model from this schema.
 */


// we can define a schema for our collection, to let Mongoose know what
// objects in the collection will look like
// The schema does not mention the _id field, that is automatically added.
const productSchema = new mongoose.Schema({
    title: { type: String, required: true },
    price: { type: Number, required: true },
    imageUrl: { type: String, required: true },
    description: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true } // user who created the product
});

module.exports = mongoose.model('Product', productSchema);
