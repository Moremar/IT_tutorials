const fs = require('fs');

// asynchronous deletion of a file
const deleteFile = (filePath) => {
    // only delete the file if it exists
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            console.log("WARNING - File " + filePath + " does not exist, nothing to delete.");
            return;
        }
        fs.unlink(filePath, (err) => {
            if (err) {
                throw (err);
            }
            console.log("Deleted file " + filePath);
        });    
    });
};


exports.deleteFile = deleteFile;