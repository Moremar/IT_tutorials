const { validationResult } = require("express-validator");
const fs = require("fs");
const path = require("path");

const Post = require("../models/post");


exports.getPosts = (req, res, next) => {
    const page = req.query.page || 1;
    const itemsPerPage = 2;
    let totalItems;
    Post.find()
    .countDocuments()
    .then((count) => {
        totalItems = count;
        return Post.find().skip((page -1) * itemsPerPage).limit(itemsPerPage);
    })
    .then((posts) => {
        res.status(200).json({
            message: "Fetched posts",
            posts: posts,
            totalItems: totalItems
        });
    })
    .catch((err) => {
        next(err);
    });
};

exports.getPost = (req, res, next) => {
    const postId = req.params.postId;
    Post.findOne({ _id: postId })
    .then((post) => {
        if (!post) {
            const error = new Error("No post found with ID " + postId);
            error.statusCode = 404;
            throw error;  // this will go to the catch() block
        }
        res.status(200).json({ message: "Post fetched", post: post });
    })
    .catch((err) => {
        next(err);
    });
};

exports.createPost = (req, res, next) => {
    // JSON error response if validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const error = new Error("Validation failed, entered title and content are not valid.");
        error.statusCode = 422;   // custom property
        throw error;
    }
    // ensure an image was uploaded by Multer
    if (!req.file) {
        const error = new Error("Upload of the post image failed.");
        error.statusCode = 422;   // custom property
        throw error;
    }
    const title = req.body.title;
    const content = req.body.content;
    const imageUrl = req.file.destination + req.file.filename;
    const post = new Post({
        title: title,
        content: content,
        imageUrl: imageUrl,
        creator: { name: "John" },
    });
    post.save()
    .then((createdPost) => {
        res.status(201).json({
            message: "Post created successfully",
            post: createdPost
        });
        })
    .catch((err) => {
        next(err);
    });
};


exports.updatePost = (req, res, next) => {
    // JSON error response if validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const error = new Error("Validation failed, entered title and content are not valid.");
        error.statusCode = 422;   // custom property
        throw error;
    }
    const postId  = req.params.postId;
    const title   = req.body.title;
    const content = req.body.content;
    let imageUrl  = req.body.image;
    if (req.file) {
        // a new image was set
        imageUrl = req.file.destination + req.file.filename;
    }
    Post.findOne({ _id: postId })
    .then((post) => {
        if (!post) {
            const error = new Error("No post found with ID = " + postId);
            error.statusCode = 404;
            throw error;
            }
        if (imageUrl != post.imageUrl) {
            // clear the old image if a new one was uploaded
            clearImage(post.imageUrl);
        }
        post.title = title;
        post.content = content;
        post.imageUrl = imageUrl;
        return post.save();
    })
    .then((updateResult) => {
        console.log("Updated existing post");
        res.status(200).json({ message: "Updated post", post: updateResult });
    })
    .catch((err) => {
        next(err);
    });
};

/**
 * Utility method to delete an image file on disk when the corresponding post was
 * deleted or when its image was replaced by a new one
 */
const clearImage = (imagePath) => {
    filePath = path.join(__dirname, "..", imagePath);
    fs.unlink(filePath, (err) => {
        console.log(err);
    });
}

exports.deletePost = (req, res, next) => {
    const postId = req.params.postId;
    Post.findOne({ _id: postId })
    .then((post) => {
        if (!post) {
            const error = new Error("No post found with ID = " + postId);
            error.statusCode = 404;
            throw error;
        }
        // TODO check logged in user
        clearImage(post.imageUrl);
        return Post.deleteOne({ _id: postId });
    })
    .then((deleteResult) => {
        console.log("Deleted existing post");
        res.status(200).json({ message: "Deleted post" });
    })
    .catch((err) => {
        next(err);
    });
}
