# Use a Node.js base image
FROM node

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file required for the "npm install" command
# It would be copied again by the "COPY . ." command later, but copying it
# before the "npm install" makes better use of the layered structure of the image :
# if the code source changes, only layers from "COPY . ." will be re-built, and
# Docker will not run again the "npm install" when dependencies did not change
COPY package.json .

# Install dependencies
RUN npm install

# Copy all code in the current folder to /app
COPY . .

# Expose the port on which the server will listen
# this setting is just for information of what ports the container can expose
# the actual port exposition is done with -p when the container is started
EXPOSE 80

# Start the server when the container is run
CMD ["node", "server.js"]