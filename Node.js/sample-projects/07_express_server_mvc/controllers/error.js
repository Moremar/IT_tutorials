const { application } = require("express")

// Controller to handle the case where the request targets an endpoint that
// is not supported by the application

exports.getNotFoundPage = (req, res, next) => {
    // use an EJS template
    res.render('not-found', {pageTitle: 'Not Found'});
};