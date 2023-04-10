
// Controller to handle the case where the request targets an endpoint that
// is not supported by the application

exports.getNotFoundPage = (req, res, next) => {
    console.log('Unhandled request URL : ' + req.method + ' ' + req.url);
    // use an EJS template
    res.render('not-found', {pageTitle: 'Not Found'});
};