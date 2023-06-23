
const express = require('express');
const bodyParser = require('body-parser');

/**
 * Very simple Node.js webapp exposing 2 endpoints :
 * GET http://localhost:80/              show a HTML page with a text input
 * POST http://localhost:80/store-goal   update a variable and redirect to GET /
 * 
 * It can be started locally with :
 *   npm install
 *   npm start
 * 
 * The goal here is to start it in a Docker container instead of locally.
 * This is done by creating a Dockerfile to create an image using the "node" image
 * as a base and starting our webapp in it.
 * 
 * docker build -t my_node_img .
 * docker run -d --name my_node_webapp --rm -p 80:80 my_node_img
 * 
 * When the container is running, access the app from http://localhost:80
 */

const app = express();

let userGoal = 'Learn Docker!';

app.use(bodyParser.urlencoded({ extended: false, }));

app.use((req, res, next) => {
  console.log(req.method + " " + req.url);
  next();
});

app.use(express.static('public'));

app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <link rel="stylesheet" href="styles.css">
      </head>
      <body>
        <section>
          <h2>My Course Goal : </h2>
          <h3>${userGoal}</h3>
        </section>
        <form action="/store-goal" method="POST">
          <div class="form-control">
            <label>Course Goal</label>
            <input type="text" name="goal">
          </div>
          <button>Set Course Goal</button>
        </form>
      </body>
    </html>
  `);
});

app.post('/store-goal', (req, res) => {
  const enteredGoal = req.body.goal;
  console.log(enteredGoal);
  userGoal = enteredGoal;
  res.redirect('/');
});

console.log("Starting listening on port 80...");
app.listen(80);
