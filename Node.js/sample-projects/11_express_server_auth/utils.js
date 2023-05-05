const fs = require('fs');

// asynchronous deletion of a file
const deleteFile = (filePath) => {
    fs.unlink(filePath, (err) => {
        if (err) {
            throw (err);
        }
    });
};


exports.deleteFile = deleteFile;