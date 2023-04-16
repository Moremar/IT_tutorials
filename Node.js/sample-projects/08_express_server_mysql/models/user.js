const Sequelize = require('sequelize');    // for type constants
const sequelize = require('../database');  // to create models

/**
 * User Sequelize model.
 * In this app, we do not have real user management, so a single user with ID 1 is created at startup and used
 * for all queries.
 * Thanks to the Sequelize associations defined in server.js, the user object has several
 * auto-generated methods to create associated objects and attach its user ID to it
 * (for example to create a cart, a product, an order ...)
 */

const User = sequelize.define('user', {
    id: { type: Sequelize.INTEGER, allowNull: false, primaryKey: true, autoIncrement: true },
    name: { type: Sequelize.STRING, allowNull: false },
    email: { type: Sequelize.STRING, allowNull: false },
});

module.exports = User;
