const socketIo = require("socket.io");

/**
 * Establish the WebSockets connection and expose the connection
 * so controllers can send events to the clients
 */

// WebSockets connection object to send events to all connected clients
let _io;


module.exports = {
    init: (httpServer) => {
        _io = socketIo(
            httpServer, {
            cors: { origin: "http://localhost:3000", methods: ["GET"] }
        });
        return _io;
    },
    getIo: () => {
        if (!_io) {
            throw new Error("Socket.io is not initialized!");
        }
        return _io;
    }
};