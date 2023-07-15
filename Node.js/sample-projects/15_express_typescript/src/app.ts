import express from 'express';
import router from './routes/todo.routes';

/**
 * Basic TODO apps written in Typescript
 * The source code is under ./src/ and the JS code is generated under ./dist/
 * "npm start" builds the JS code and starts the Node server using ./dist/app.js
 */

const app = express();

// parse JSON body (modern alternative to the body-parser package)
app.use(express.json());

// use the registered routes for the /todo prefix
app.use('/todo', router);

app.listen(3000, () => {
    console.log('Server running on port 3000');
});