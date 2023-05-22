const jwt = require("jsonwebtoken");

/**
 * Middleware used by all endpoints requiring authentication
 * It checks the existence of the JWT token in the Authorization header
 * If the user is authenticated, it sets req.isAuth to true and sets req.userId
 */
module.exports = (req, res, next) => {
    const authHeader = req.get("Authorization");
    if (!authHeader) {
        req.isAuth = false;
        return next();
    }
    // the "Authorization" header looks like "Bearer <token>" so we keep only the token part
    const token = authHeader.split(" ")[1];
    let decodedToken;
    try {
        // verify() both decodes and checks the token
        decodedToken = jwt.verify(token, process.env.JWT_KEY);
    } catch (err) {
        req.isAuth = false;
        return next();
    }
    if (!decodedToken) {
        req.isAuth = false;
        return next();
    }
    // enrich the request with the user ID
    req.userId = decodedToken.userId;
    req.isAuth = true;
    return next();
};