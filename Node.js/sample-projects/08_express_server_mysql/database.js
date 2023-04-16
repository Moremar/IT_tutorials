// constructor for a wrapper above an SQL database providing ORM features
const Sequelize = require('sequelize').Sequelize;

/**
 * The MySQL database is wrapped by the Sequelize ORM library
 * Instead of sending raw SQL queries, we interact with the DB only via
 * Sequelize models (one model class for each DB table).
 * 
 * This requires the connection parameters to be defined in the .env file.
 * This file is not included in the git repository.
 * Once we have a MySQL server running, we must specify in the .env file :
 * 
 *    MYSQL_HOST="localhost"
 *    MYSQL_USER="root"
 *    MYSQL_PASSWORD="mypassword"
 *    MYSQL_SCHEMA="schemanodejs"
 */


// instance of the Sequelize ORM wrapper for a given database
const sequelize = new Sequelize(
    process.env.MYSQL_SCHEMA,
    process.env.MYSQL_USER,
    process.env.MYSQL_PASSWORD,
    {
        dialect: 'mysql',
        host: process.env.MYSQL_HOST
    }
);

module.exports = sequelize;