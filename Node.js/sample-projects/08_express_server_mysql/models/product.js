const Sequelize = require('sequelize');    // for constants
const sequelize = require('../database');  // to create models

/**
 * Sequelize Model, ORM wrapper above the "products" DB table in the DB.
 * It contains all fields of a product, and also a userId field added automatically
 * by Sequelize from the association in server.js.
 */

const Product = sequelize.define('product', {
    id: { type: Sequelize.INTEGER, allowNull: false, primaryKey: true, autoIncrement: true },
    title: { type: Sequelize.STRING, allowNull: false },
    price: { type: Sequelize.DOUBLE, allowNull: false },
    imageUrl: { type: Sequelize.STRING, allowNull: false },
    description: { type: Sequelize.STRING, allowNull: false }
});

module.exports = Product;
