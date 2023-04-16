const Sequelize = require('sequelize');    // for constants
const sequelize = require('../database');  // to create models

/**
 * Sequelize Model representing an item in an order (very similar to cart-item.js)
 * It has an orderId and a productId fields added automatically by associations in server.js.
 * The only additional information to keep track of at item level is the quantity of a given product in the order.
 * 
 * It does not need a unique ID as it is just an intermediate table for a N-to-M association.
 * Its primary key in the DB will be (orderId, productId) that Sequelize can infer from the associations.
 */


const OrderItem = sequelize.define('orderItem', {
    quantity: { type: Sequelize.INTEGER, allowNull: false }
});

module.exports = OrderItem;
