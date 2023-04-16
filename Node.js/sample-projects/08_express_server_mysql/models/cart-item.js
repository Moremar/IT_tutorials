const Sequelize = require('sequelize');    // for constants
const sequelize = require('../database');  // to create models

/**
 * Sequelize Model representing an item in a cart.
 * It has a cartId and a productId fields added automatically by associations in server.js.
 * The only additional information to keep track of at item level is the quantity of a given product in the cart.
 * 
 * It does not need a unique ID as it is just an intermediate table for a N-to-M association.
 * Its primary key in the DB will be (cartId, productId) that Sequelize can infer from the associations.
 */

const CartItem = sequelize.define('cartItem', {
    quantity: { type: Sequelize.INTEGER, allowNull: false }
});

module.exports = CartItem;
