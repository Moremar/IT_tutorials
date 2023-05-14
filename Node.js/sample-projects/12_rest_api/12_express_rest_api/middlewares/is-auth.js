const jwt = require("jsonwebtoken");

/**
 * Middleware used by all endpoints requiring authentication
 * It checks the existence of the JWT token in the Authorization header
 * It only lets the request go through if the JWT token exists and is valid
 */
module.exports = (req, res, next) => {
    const authHeader = req.get("Authorization");
    if (!authHeader) {
        const error = new Error("Not Authenticated");
        error.statusCode = 401;  // not authenticated
        next(error);
    }
    // the "Authorization" header looks like "Bearer <token>" so we keep only the token part
    const token = authHeader.split(" ")[1];
    let decodedToken;
    try {
        // verify() both decodes and checks the token
        decodedToken = jwt.verify(token, process.env.JWT_KEY);
    } catch (err) {
        next(err);
    }
    if (!decodedToken) {
        const error = new Error("Not Authenticated");
        error.statusCode = 401;  // not authenticated
        next(error);
    }
    // enrich the request with the user ID, and allow the request to continue
    req.userId = decodedToken.userId;
    next()
};