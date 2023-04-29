/**
 * Custom middleware to check if a user is logged in
 * If he is not, redirect to the login page
 */

module.exports = (req, res, next) => {
    if (!req.session.isAuthenticated) {
        console.log("WARNING : User not authenticated - Redirect to login page");
        req.flash('error', 'This action requires to be authenticated.');
        return res.redirect("/login");
    }
    console.log("User is authenticated - Access granted");
    next();
};