// include required modules as constants
const http = require('http');
const fs   = require('fs');

/**
 * started with :   node server.js
 * 
 * This server uses pure Node.js only, without the Express framework
 * It starts a server that listens to 2 routes :
 *   GET /admin/add      : return an HTML page with a form containing a message field
 *                         on submit, it calls POST /message
 *   POST /admin/message : extract the submitted message and save it to a file
 *                         return a 302 success code
 */


// create the callback handling the request
// this could be in a separate file imported with require()
const routesHandler = (req, res) => {

    // get required info from the request
    const url = req.url;
    const method = req.method;
    console.log(method + " " + url);

    // Return an HTML form with a message input for the root URL
    if (url === "/admin/add") {
        const htmlResponse = 
            '<html>'
            + '  <head><title>Enter Message</title></head>'
            + '  <body>'
            + '    <form action="/admin/message" method="POST">'
            + '      <input type="text" name="mess"/>'
            + '      <button type="submit">Send</button>'
            + '    </form>'
            + '  </body>'
            + '</html>';

        // prepare the HTTP response
        res.write(htmlResponse);
        return res.end();
    }

    // extract the message when receiving the submission from the HTML form
    if (url === '/admin/message' && method == 'POST') {
        // listen to the reception of data in the request stream to build the body
        // this is a bit tedious and is no longer required when using Express with the
        // "body-parser" middleware
        const body = [];
        req.on('data', (chunk) => {
            body.push(chunk);
        });
        // when the data is fully received, buffer it and save it to file
        // we return the promise so, Node.js does not execute the code after it
        return req.on('end', () => {
            const parsed = Buffer.concat(body).toString();
            // the parsed body has the form "mess=XXX"
            // save the part after the = to a local file (async method)
            const message = parsed.split('=')[1];
            fs.writeFile("message.txt", message, (err) => {
                // prepare the HTTP response
                res.statusCode = 302;
                const htmlResponse = "<p><b>Message saved : </b>" + message + "</p>";
                res.write(htmlResponse);
                return res.end();
            });
        });
    }

    // for any other potential HTTP request
    return res.end();
};


// create the HTTP server with the callback to execute for each incoming HTTP request
const server = http.createServer(routesHandler);

// loop listening for request on a given port
server.listen(3000);
