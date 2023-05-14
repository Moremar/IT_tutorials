const express = require("express");
const { body } = require("express-validator");

const feedsController = require("../controllers/feed");


const router = express.Router();

// GET /feed/posts
// retrieve all posts
router.get("/posts", feedsController.getPosts);

// GET /feed/posts/:postId
// retrieve a single post
router.get("/posts/:postId", feedsController.getPost);

// POST /feed/posts
router.post("/posts",
  [
    body("title").trim().isLength({ min: 5 }),
    body("content").trim().isLength({ min: 5 }),
  ],
  feedsController.createPost);

// PUT /feed/posts/:postId
// update a single post
router.put("/posts/:postId",
  [
    body("title").trim().isLength({ min: 5 }),
    body("content").trim().isLength({ min: 5 }),
  ],
  feedsController.updatePost);

// DELETE /feed/posts/:postId
// delete a single post
router.delete("/posts/:postId",
  feedsController.deletePost);


module.exports = router;