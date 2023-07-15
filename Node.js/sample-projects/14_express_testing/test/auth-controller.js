const { expect } = require('chai');
const sinon = require('sinon');
const bcrypt = require("bcryptjs");

const mongoose = require('mongoose');
const User = require('../models/user');
const AuthController = require('../controllers/auth');


describe('Auth Controller - Login', function() {

    // hook that runs once before the test suite
    before(function(done) {
        // increase the timeout for this test, since it needs to connect to the DB
        this.timeout(10000);

        // load custom env variables into process.env and override
        // the database to use a dedicated one for unit tests
        // (we could also have a totally different instance for tests)
        const dotenv = require('dotenv');
        dotenv.config();
        process.env.MONGODB_DATABASE = "schemanodejs_unit_test";

        // connect to MongoDB
        const mongoUser = process.env.MONGODB_USER;
        const mongoPassword = process.env.MONGODB_PASSWORD;
        const mongoHost = process.env.MONGODB_HOST;
        const mongoDatabase = process.env.MONGODB_DATABASE;
        const uri = "mongodb+srv://" + mongoUser + ":" + mongoPassword +
            "@" + mongoHost + "/" + mongoDatabase + "?retryWrites=true&w=majority";
        mongoose.connect(uri)
            .then(() => {
                // create a test user
                const testUser = new User({
                    name: "tester",
                    email: "test@test.com",
                    password: bcrypt.hashSync("tester", 12),
                    status: "NEW",
                    posts: []
                });
                return testUser.save();
            })
            .then(() => {
                // mark the initialization as complete
                done();
            });
    });


    // hook that runs once after the test suite
    after(function(done) {
        // delete the test user
        User.deleteMany({})
            .then(() => {
                // disconnect the DB
                return mongoose.disconnect();
            })
            .then(() => {
                // mark the finalization as complete
                done();
            });
    });


    // unit test that stubs the DB (no actual MongoDB used)
    it('should throw an error with code 500 if accessing the database fails', function(done) {
        sinon.stub(User, 'findOne');
        User.findOne.throws();

        const req = { body: { email: 'test@test.com', password: 'tester' } };

        AuthController.login(req, {}, () => {})
            .then(result => {
                expect(result).to.be.an('error');
                expect(result).to.have.property('statusCode', 500);
                // method provided by Mocha in parameter that we can call to wait
                // for the execution of async code
                done();
            });

        User.findOne.restore();
    });


    // this test does not mock the Mongo DB
    // instead it uses the unit_test database inside the Mongo DB
    it('should return a response for a valid user', function(done) {
        // login with the test user
        const req = { body: { email: 'test@test.com', password: 'tester' } };
        const res = {
            status: function(x) { this.statusCode = x; return this; },
            json: function(x) { this.token = x.token; return this; }
        };
        AuthController.login(req, res, () => {})
            .then(result => {
                // check the login result
                expect(result).to.have.property('statusCode', 200);
                expect(result).to.have.property('token');
                done();
            });
    })
});