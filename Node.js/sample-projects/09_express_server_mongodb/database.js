const mongodb = require('mongodb');

/**
 * MongoDB database using the native "mongodb" Node.js driver module.
 * 
 * This requires the connection parameters to be defined in the .env file.
 * This file is not included in the git repository.
 * Once we have a MySQL server running, we must specify in the .env file :
 * 
 *    MONGODB_HOST="localhost"
 *    MONGODB_USER="nodejsdev"
 *    MONGODB_PASSWORD="mypassword"
 *    MONGODB_DATABASE="schemanodejs"
 */

// internal variable, exposed via the getDb() method
let _db;

const connect = (callbackFn) => {
    const mongoUser     = process.env.MONGODB_USER;
    const mongoPassword = process.env.MONGODB_PASSWORD;
    const mongoHost     = process.env.MONGODB_HOST;
    const mongoDatabase = process.env.MONGODB_DATABASE;
    const uri = "mongodb+srv://" + mongoUser + ":" + mongoPassword
              + '@' + mongoHost + "/?retryWrites=true&w=majority";

    const mongoClient = new mongodb.MongoClient(uri);
    mongoClient.connect()
    .then((client) => {
        console.log('Connected to the MongoDB server');
        _db = client.db(mongoDatabase);
        callbackFn();
    })
    .catch((err) => {
        console.log('ERROR - Could not connect to the mongoDB server');
        console.log(err);
    });
};

const getDb = () => {
    if (_db) {
        return _db;
    }
    throw 'Need to call connect() before accessing the database';
}

exports.connect = connect;
exports.getDb = getDb;