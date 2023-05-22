const bcrypt    = require("bcryptjs");
const validator = require("validator");
const jwt       = require("jsonwebtoken");

const fileUtil = require("../utils/file");

const User = require("../models/user");
const Post = require("../models/post");

/**
 * The resolvers correspond to the controllers in a normal REST API.
 * They are the functions referenced by the GraphQL schema.
 * They receive as input the arguments from the schema and the HTTP request.
 */

module.exports = {

    // here we use an async function so we can use await instead of the then/catch structure
    signup: async function(args, req) {
        // extract data from request
        const email    = args.userInput.email;
        const name     = args.userInput.name;
        const password = args.userInput.password;
        // data validation
        const errors = [];
        if (!validator.isEmail(email)) {
            errors.push({ message: "Invalid email" });
        }
        if (validator.isEmpty(password) || !validator.isLength(password, { min: 5 })) {
            errors.push({ message: "Password too short" });
        }
        if (errors.length > 0) {
            const error = new Error("Invalid input");
            error.data = errors; // store the messages for display in the response
            error.code = 422;
            throw error;
        }
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            const error = new Error("User already exists");
            throw error;
        }
        const hashedPassword = await bcrypt.hash(password, 12);
        const user = new User({
            email: email,
            password: hashedPassword,
            name: name,
            status: "NEW"
        });
        const createdUser = await user.save();
        return { ...createdUser._doc, _id: createdUser._id.toString() };
    },


    login: async function(args, req) {
        // extract data from request
        const email    = args.email;
        const password = args.password;
        const user = await User.findOne({ email: email });
        if (!user) {
            const error = new Error("The user does not exist");
            error.code = 401;
            throw error;
        }
        // check the password
        const matches = await bcrypt.compare(password, user.password);
        if (!matches) {
            const error = new Error("Incorrect password");
            error.code = 401;
            throw error;
        }
        // generate a JWT webtoken
        const token = jwt.sign({
            email: email,
            userId: user._id.toString()
          }, 
          // secret key used on server-side to encrypt and decrypt JWT tokens
          process.env.JWT_KEY,
          // JWT token options
          { expiresIn: "1h" }
        );
        return { token: token, userId: user._id.toString() };
    },


    createPost: async function (args, req) {
        // validate that the user is authenticated
        if (!req.isAuth) {
            const error = new Error("Not authenticated");
            error.code = 401;
            throw error;
        }
        // validate the input
        const title    = args.postInput.title;
        const content  = args.postInput.content;
        const imageUrl = args.postInput.imageUrl;
        const errors = [];
        if (validator.isEmpty(title) || !validator.isLength(title, { min: 5 })) {
            errors.push({ message: "Invalid title" });
        }
        if (validator.isEmpty(content) || !validator.isLength(content, { min: 5 })) {
            errors.push({ message: "Invalid content" });
        }
        if (errors.length > 0) {
            const error = new Error("Invalid post");
            error.data = errors; // store the messages for display in the response
            error.code = 422;
            throw error;
        }
        // the user is authenticated so we can retrieve it from the DB
        const user = await User.findOne({ _id: req.userId });
        if (!user) {
            const error = new Error("Invalid user");
            error.code = 401;
            throw error;
        }
        const post = new Post({ title: title, content: content, imageUrl: imageUrl, creator: user });
        const createdPost = await post.save();
        user.posts.push(createdPost);
        await user.save();
        return {
            ...createdPost._doc,
            _id: createdPost._id.toString(),
            createdAt: createdPost.createdAt.toISOString(),
            updatedAt: createdPost.updatedAt.toISOString()
         };
    },


    updatePost: async function(args, req) {
        // validate that the user is authenticated
        if (!req.isAuth) {
            const error = new Error("Not authenticated");
            error.code = 401;
            throw error;
        }
        // validate the input
        const title    = args.postInput.title;
        const content  = args.postInput.content;
        const imageUrl = args.postInput.imageUrl;
        const errors = [];
        if (validator.isEmpty(title) || !validator.isLength(title, { min: 5 })) {
            errors.push({ message: "Invalid title" });
        }
        if (validator.isEmpty(content) || !validator.isLength(content, { min: 5 })) {
            errors.push({ message: "Invalid content" });
        }
        if (errors.length > 0) {
            const error = new Error("Invalid post");
            error.data = errors; // store the messages for display in the response
            error.code = 422;
            throw error;
        } 
        // ensure the post to update exists
        const postId = args.postId;
        const post = await Post.findOne({ _id: postId }).populate("creator");
        if (!post) {
            const error = new Error("No post found with ID " + postId);
            error.code = 404;
            throw error;            
        }
        // ensure the post to edit belongs to the current user
        if (post.creator._id.toString() !== req.userId) {
            const error = new Error("Not authorized to edit post with ID " + postId);
            error.code = 403;
            throw error;
        }
        post.title = title;
        post.content = content;
        if (imageUrl != "undefined") {
            post.imageUrl = imageUrl;
        }
        const updatedPost = await post.save();
        return {
            ...updatedPost._doc,
            _id: updatedPost._id.toString(),
            creator: { ...updatedPost.creator._doc, _id: updatedPost.creator._id.toString() },
            createdAt: updatedPost.createdAt.toISOString(),
            updatedAt: updatedPost.updatedAt.toISOString()
        };
    },


    deletePost: async function(args, req) {
        // validate that the user is authenticated
        if (!req.isAuth) {
            const error = new Error("Not authenticated");
            error.code = 401;
            throw error;
        }
        // ensure the post to update exists
        const postId = args.postId;
        const post = await Post.findOne({ _id: postId });
        if (!post) {
            const error = new Error("No post found with ID " + postId);
            error.code = 404;
            throw error;            
        }
        // ensure the post to edit belongs to the current user
        if (post.creator.toString() !== req.userId) {
            const error = new Error("Not authorized to delete post with ID " + postId);
            error.code = 403;
            throw error;
        }
        fileUtil.clearImage(post.imageUrl);
        await Post.deleteOne({ _id: postId  });
        const user = await User.findOne({ _id: req.userId });
        user.posts.pull(postId);
        await user.save();
        return true;
    },


    getPosts: async function(args, req) {
        // validate that the user is authenticated
        if (!req.isAuth) {
            const error = new Error("Not authenticated");
            error.code = 401;
            throw error;
        }
        const page = args.page || 1;
        const itemsPerPage = 2;
        const totalItems = await Post.find().countDocuments();
        const posts = await Post.find()
                                .sort({ createdAt: -1 })
                                .skip((page -1) * itemsPerPage)
                                .limit(itemsPerPage)
                                .populate("creator");
        return {
            posts: posts.map(post => {
                return {
                    ...post._doc,
                    _id: post._id.toString(),
                    creator: { ...post.creator._doc, _id: post.creator._id.toString() },
                    createdAt: post.createdAt.toISOString(),
                    updatedAt: post.updatedAt.toISOString()
                }
            }),
            totalItems: totalItems
        };
    },

    getPost: async function(args, req) {
        // validate that the user is authenticated
        if (!req.isAuth) {
            const error = new Error("Not authenticated");
            error.code = 401;
            throw error;
        }
        const postId = args.postId;
        const post = await Post.findOne({ _id: postId }).populate("creator");
        if (!post) {
            const error = new Error("No post found with ID " + postId);
            error.code = 404;
            throw error;
        }
        return {
            ...post._doc,
            _id: post._id.toString(),
            creator: { ...post.creator._doc, _id: post.creator._id.toString() },
            createdAt: post.createdAt.toISOString(),
            updatedAt: post.updatedAt.toISOString()
        };
    }
};
