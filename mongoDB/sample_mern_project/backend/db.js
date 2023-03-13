const mongodb = require('mongodb');

const MongoClient = mongodb.MongoClient;

// connection string to access mongoDB
// use 0.0.0.0 IP address to check all available network interfaces
// use "admin" database because that is the database where the "appdev" user is created
const MONGODB_URL = 'mongodb://appdev:appdev@0.0.0.0:27017/admin?directConnection=true';

let _client;

const initClient = (callback) => {
    if (_client) {
        // already initialized
        return callback(null, _client);
    }
    MongoClient
       .connect(MONGODB_URL)
       .then(
        (client) => {
            // use the same client for all request to use connection pooling
            _client = client;
            callback(null, _client);
        }
       )
       .catch(
        (err) => {
            callback(err);
        }
       );
}

const getClient = () => {
    if (!_client) {
        throw Error("Database client not initialized");
    }
    return _client;
}

module.exports = { initClient, getClient }