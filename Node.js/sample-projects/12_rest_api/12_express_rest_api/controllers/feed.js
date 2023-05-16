const { validationResult } = require("express-validator");
const fs = require("fs");
const path = require("path");

const Post = require("../models/post");
const User = require("../models/user");

const io = require("../socket");


exports.getPosts = (req, res, next) => {
    const page = req.query.page || 1;
    const itemsPerPage = 2;
    let totalItems;
    Post.find()
    .countDocuments()
    .then((count) => {
        totalItems = count;
        return Post.find()
                   .populate("creator")
                   .sort({ createdAt: -1 })
                   .skip((page - 1) * itemsPerPage)
                   .limit(itemsPerPage);
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
    let creator;
    const title = req.body.title;
    const content = req.body.content;
    const imageUrl = req.file.destination + req.file.filename;
    const post = new Post({
        title: title,
        content: content,
        imageUrl: imageUrl,
        creator: req.userId
    });
    post.save()
    .then((createdPost) => {
        return User.findOne({ _id: req.userId });
    })
    .then((user) => {
        // update the user with the new post he created
        user.posts.push(post);
        creator = user;
        return user.save();
    })
    .then(() => {
        // inform all connected clients via WebSockets that a new post was created,
        // so they can refresh their UI
        io.getIo().emit("posts", {
            action: "create",
            // enrich the post with creator name for the UI
            post: { ...post._doc, creator: {_id: req.userId, name: creator.name } }
        });
        // send the HTTP response
        res.status(201).json({
            message: "Post created successfully",
            post: post,
            creator: { _id: creator._id, name: creator.name }
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
    let updatedPost;
    Post.findOne({ _id: postId }).populate("creator")
    .then((post) => {
        if (!post) {
            const error = new Error("No post found with ID = " + postId);
            error.statusCode = 404;
            throw error;
        }
        if (post.creator._id.toString() !== req.userId) {
            // a user can only update his own posts
            const error = new Error("Not Authorized");
            error.statusCode = 403;
            throw error;
        }
        if (imageUrl != post.imageUrl) {
            // clear the old image if a new one was uploaded
            clearImage(post.imageUrl);
        }
        post.title = title;
        post.content = content;
        post.imageUrl = imageUrl;
        updatedPost = post;
        return post.save();
    })
    .then((updateResult) => {
        console.log("Updated existing post");
        // inform all connected clients via WebSockets that a post was updated,
        // so they can refresh their UI
        io.getIo().emit("posts", {
            action: "update",
            post: updatedPost
        });
        // send the HTTP response
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
        if (post.creator.toString() !== req.userId) {
            // a user can only delete his own posts
            const error = new Error("Not Authorized");
            error.statusCode = 403;
            throw error;
        }
        clearImage(post.imageUrl);
        return Post.deleteOne({ _id: postId });
    })
    .then((deleteResult) => {
        return User.findOne({ _id: req.userId });
    })
    .then((user) => {
        // remove the deleted post from the user object
        user.posts.pull(postId);
        return user.save();
    })
    .then((result) => {
        console.log("Deleted existing post");
        // inform all connected clients via WebSockets that a post was deleted,
        // so they can refresh their UI
        io.getIo().emit("posts", {
            action: "delete",
            post: postId
        });
        // send the HTTP response
        res.status(200).json({ message: "Deleted post" });
    })
    .catch((err) => {
        next(err);
    });
}
