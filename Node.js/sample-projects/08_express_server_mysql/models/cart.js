const Sequelize = require('sequelize');    // for constants
const sequelize = require('../database');  // to create models

/**
 * Sequelize Model, ORM wrapper above the "carts" DB table in the DB.
 * 
 * There will only be a single cart instance in the app, since we use a single user.
 * The cart has many products in it, so the cart items are stored in another table,
 * specified by the cart-item.js model.
 * There is no specific data to keep track at cart level, except the user ID, that is added
 * by the association in server.js, so it does not need to be added explicitely here.
 */


const Cart = sequelize.define('cart', {
    id: { type: Sequelize.INTEGER, allowNull: false, primaryKey: true, autoIncrement: true }
});

module.exports = Cart;
