const { expect } = require('chai');
const jwt = require('jsonwebtoken');
const sinon = require('sinon');

const isAuth = require('../middlewares/is-auth');

// Unit test group
describe('Auth middleware', function() {

    // individual unit test
    it('should throw an error when no Authorization header', function() {
        // create a fake request with only the get method we care about
        // we check the bahavior when get() returns null
        const req = {
            get: function(headerName) { return null; }
        };
        // do not call the function ourselves, just bind its args and let Chai call it
        expect(isAuth.bind(this, req, {}, () => {})).to.throw('Not Authenticated');
    });

    it('should throw an error when single-chunk Authorization header', function() {
        // we check the bahavior when get() returns a single-chunk string
        const req = {
            get: function(headerName) { return 'abc'; }
        };
        expect(isAuth.bind(this, req, {}, () => {})).to.throw();
    });

    it('should throw an error when the JWT token is incorrect', function() {
        // we check the bahavior when get() returns an incorrect token
        const req = {
            get: function(headerName) { return 'Bearer abc'; }
        };
        expect(isAuth.bind(this, req, {}, () => {})).to.throw();
    });

    it('should add a userId property successful auth', function() {
        // we check the bahavior when get() returns an correct token
        const req = {
            get: function(headerName) { return 'Bearer abcdef'; }
        };
        // we stub jwt.verify() so it returns an object with a userId field
        sinon.stub(jwt, 'verify');
        jwt.verify.returns({ userId: 'xxx' });

        isAuth(req, {}, () => {});
        expect(req).to.have.property('userId', 'xxx');
        expect(jwt.verify.called).to.be.true;

        // remove the stub so other tests are not impacted
        jwt.verify.restore();
    });
});