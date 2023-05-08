const express = require("express");

const feedsController = require("../controllers/feed");


const router = express.Router();

// GET /feed/posts
router.get("/posts", feedsController.getPosts);

// POST /feed/posts
router.post("/posts", feedsController.createPost);


module.exports = router;