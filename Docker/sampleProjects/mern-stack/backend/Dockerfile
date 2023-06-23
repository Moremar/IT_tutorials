# Node.js app based on the node image
FROM node

# all app-specific code will be in the /app folder inside the image
WORKDIR /app

# first copy the package.json required to run "npm install"
COPY package.json .

# create the node_modules folder with all NPM dependencies
RUN npm install

# copy source code to the container
COPY . .

# expose port 80 where the webserver is running
EXPOSE 80

# environment variables expected at container creation
ENV MONGO_INITDB_ROOT_USERNAME=mongo_user
ENV MONGO_INITDB_ROOT_USERNAME=mongo_password

# at startup, run the web server
CMD ["npm", "start"]


