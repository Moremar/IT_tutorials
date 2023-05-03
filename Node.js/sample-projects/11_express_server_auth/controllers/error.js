
// Controller to handle the case where the request targets an endpoint that
// is not supported by the application
exports.getNotFoundPage = (req, res, next) => {
    console.log('Unhandled request URL : ' + req.method + ' ' + req.url);
    // use an EJS template
    res.render('not-found', {pageTitle: 'Not Found'});
};


// Error-handling controller
// called when an error is thrown synchronously in a middleware, or when next(error) is called
exports.getServerErrorPage = (error, req, res, next) => {
    console.log('Server error occured in call ' + req.method + ' ' + req.url);
    console.log(error);
    // use an EJS template
    res.render('server-error', {pageTitle: 'Server error'});
};