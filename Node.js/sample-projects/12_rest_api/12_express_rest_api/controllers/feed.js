exports.getPosts = (req, res, next) => {
    // TODO read from a DB instead
    res.status(200).json({
        posts: [{ title: "My first post", content: "This is the filrst post !"}]
    });
};

exports.createPost = (req, res, next) => {
    const title = req.body.title;
    const content = req.body.content;
    // TODO create in DB
    res.status(201).json({
        message: "Post created successfully",
        post: { id: 12345, title: title, content: content }
    });
};

