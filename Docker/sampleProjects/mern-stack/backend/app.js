const fs = require('fs');
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const morgan = require('morgan');

const Goal = require('./models/goal');

/**
 * MERN webapp designed to be containerized with Docker
 * 
 * Create a network for the app :
 *   docker network create mern_network
 * 
 * Run a MongoDB container :
 *   docker run -d --rm --name mern_mongodb --network mern_network -v mern_mongodb_data:/data/db
 *              -e MONGO_INITDB_ROOT_USERNAME=admin -e MONGO_INITDB_ROOT_PASSWORD=password mongo
 * 
 * Create an image for the backend :
 *   docker build -t mern_backend_img .
 * 
 * Run the backend container :
 *   docker run -d --rm --name mern_backend --network mern_network -p 80:80 -v mern_backend_logs:/app/logs
 *              -e MONGO_INITDB_ROOT_USERNAME=admin  -e MONGO_INITDB_ROOT_PASSWORD=password mern_backend_img
 * 
 * Create an image for the frontend :
 *   docker build -t mern_frontend_img .
 * 
 * Run the frontend :
 * docker run -d --rm -it --name mern_frontend -p 3000:3000 mern_frontend_img
 * 
 */

const app = express();

const accessLogStream = fs.createWriteStream(
  path.join(__dirname, 'logs', 'access.log'),
  { flags: 'a' }
);

app.use(morgan('combined', { stream: accessLogStream }));

app.use(bodyParser.json());

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

app.get('/goals', async (req, res) => {
  console.log('TRYING TO FETCH GOALS!!');
  try {
    const goals = await Goal.find();
    res.status(200).json({
      goals: goals.map((goal) => ({
        id: goal.id,
        text: goal.text,
      })),
    });
    console.log('FETCHED GOALS');
  } catch (err) {
    console.error('ERROR FETCHING GOALS');
    console.error(err.message);
    res.status(500).json({ message: 'Failed to load goals.' });
  }
});

app.post('/goals', async (req, res) => {
  console.log('TRYING TO STORE GOAL');
  const goalText = req.body.text;

  if (!goalText || goalText.trim().length === 0) {
    console.log('INVALID INPUT - NO TEXT');
    return res.status(422).json({ message: 'Invalid goal text.' });
  }

  const goal = new Goal({
    text: goalText,
  });

  try {
    await goal.save();
    res
      .status(201)
      .json({ message: 'Goal saved', goal: { id: goal.id, text: goalText } });
    console.log('STORED NEW GOAL');
  } catch (err) {
    console.error('ERROR FETCHING GOALS');
    console.error(err.message);
    res.status(500).json({ message: 'Failed to save goal.' });
  }
});

app.delete('/goals/:id', async (req, res) => {
  console.log('TRYING TO DELETE GOAL');
  try {
    await Goal.deleteOne({ _id: req.params.id });
    res.status(200).json({ message: 'Deleted goal!' });
    console.log('DELETED GOAL');
  } catch (err) {
    console.error('ERROR FETCHING GOALS');
    console.error(err.message);
    res.status(500).json({ message: 'Failed to delete goal.' });
  }
});

// use the mongoDB container name as host name since it is in the same network
let mongoUser = process.env.MONGO_INITDB_ROOT_USERNAME;
let mongoPwd = process.env.MONGO_INITDB_ROOT_PASSWORD;
let mongoAuthDb = "admin";
mongoose.connect(
  `mongodb://${mongoUser}:${mongoPwd}@mern_mongodb:27017/goals?authSource=${mongoAuthDb}`,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true
  },
  (err) => {
    if (err) {
      console.error('FAILED TO CONNECT TO MONGODB');
      console.error(err);
    } else {
      console.log('CONNECTED TO MONGODB');
      app.listen(80);
    }
  }
);
