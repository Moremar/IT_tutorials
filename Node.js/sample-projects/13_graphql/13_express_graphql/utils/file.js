const fs = require("fs");
const path = require("path");


/**
 * Utility method to delete an image file on disk when the corresponding post was
 * deleted or when its image was replaced by a new one
 */
exports.clearImage = (imagePath) => {
    filePath = path.join(__dirname, "..", imagePath);
    fs.unlink(filePath, (err) => {
        console.log(err);
    });
}
