const mongoose = require('mongoose');

/**
 * MongoDB database using the Mongoose ODM module.
 * 
 * Mongoose exposes a connect() method, so we only call it here with the MongoDB
 * credentials from the config file.
 * 
 * This requires the connection parameters to be defined in the .env file.
 * This file is not included in the git repository.
 * Once we have a MongoDB server running, we must specify in the .env file :
 * 
 *    MONGODB_HOST="localhost"
 *    MONGODB_USER="nodejsdev"
 *    MONGODB_PASSWORD="mypassword"
 *    MONGODB_DATABASE="schemanodejs"
 */

const connect = (callbackFn) => {
    const mongoUser     = process.env.MONGODB_USER;
    const mongoPassword = process.env.MONGODB_PASSWORD;
    const mongoHost     = process.env.MONGODB_HOST;
    const mongoDatabase = process.env.MONGODB_DATABASE;
    const uri = "mongodb+srv://" + mongoUser + ":" + mongoPassword
              + "@" + mongoHost + "/" + mongoDatabase + "?retryWrites=true&w=majority";

    mongoose.connect(uri)
    .then(() => {
        console.log('Connected to the MongoDB server');
        callbackFn();
    })
    .catch((err) => {
        console.log('ERROR - Could not connect to the mongoDB server');
        console.log(err);
    });
};

exports.connect = connect;
