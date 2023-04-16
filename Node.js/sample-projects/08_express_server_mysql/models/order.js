const Sequelize = require('sequelize');    // for constants
const sequelize = require('../database');  // to create models

/**
 * Sequelize Model, ORM wrapper above the "orders" DB table in the DB.
 * 
 * When a user clicks "Order Now" in the cart page, it creates an order with all ordered items.
 * An order contains many products, and a product can belong to many items, so this
 * N-to-M asociation is represented by the orderItems intermediate table.
 * 
 * At order level, we only keep track of the order date.
 * The userId of the order is added by the association in server.js.
 */


const Order = sequelize.define('order', {
    id: { type: Sequelize.INTEGER, allowNull: false, primaryKey: true, autoIncrement: true },
    orderDate: { type: Sequelize.DATE, allowNull: false }
});

module.exports = Order;
