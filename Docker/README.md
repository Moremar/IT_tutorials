# Docker Tutorial


## Introduction

Docker is a light-weight platform for creating and managing application containers.  
It can run on top of any OS and offers software isolation and portability.  
It solves the problem of "It runs on my machine but not on yours".

A container is a standardized self-contained running unit of software.  
It can include scripts, binaries, and any dependencies needed to run the software.  
A container runs stand-alone, independently of the machine it runs on.

A container can run on any machine that runs Docker, on any OS.  
The same container always behave in the exact same way on any machine where it is deployed.

Each container contains a specific version of every binary or library it uses (JDK, Node.js, ...).  
For example, a container can use Python 3, while another container running on the same machine uses Python 2.7.

This ensures that the code tested on one machine works the same way on any other machine.  
This also ensures that all developers and testers use the exact same development environment.  


## Docker Components

- **Docker Engine** : main Docker process, managing the running containers
- **Docker Desktop** : GUI to monitor containers and images running on the machine
- **Docker CLI** : Command-Line Interface to interact with Docker via the `docker` command
- **Docker Container** : lightweight self-contained application running on Docker
- **Docker Image** : blueprint of a container specifying its content and behavior
- **Dockerfile** : file containing the instructions to build a custom Docker image
- **Docker Hub** : official registry for Docker images
- **Docker-Compose** : tool to orchestrate several containers running and interacting together

Docker uses a client/server architecture.  
The Docker engine is the server, it needs to run all the time for Docker to be used.  
The Docker CLI and Docker Desktop are the clients, they send requests to the Docker engine that processes them.  
All actions on Docker (start/stop a container, download an image...) are performed by the Docker engine when requested by a client.


### Containers VS Virtual Machines (VM)

VMs are another virtualization mechanism to isolate an application with its dedicated dependencies.  
Containers are functionally similar to VMs, but they are more light-weight.  

VMs are installed on a host machine on top of its OS.  
Each VM ships with its own OS, containing all libraries, dependencies and apps it needs.  
VM configuration can be shared to run the exact same VM on another machine, offering portability.

If multiple VMs run on a host, they each have their dedicated guest OS.  
This implies a heavy use of CPU, RAM and hard drive space to run multiple VMs in parallel.

With Docker, the Docker engine runs on top of the host machine OS.  
All containers run on top of the Docker engine, and do not ship with a dedicated OS.  
They only contains libraries/tools/dependencies, and the app to run.

Docker containers are easier to share than VMs, as we can build and share Docker images.  
From a Docker image, anyone can start a container that behaves in a similar way on any machine. 


## Docker Installation

From the [Docker website](https://www.docker.com/), download the Docker Desktop.  
The Docker Desktop is a GUI to monitor containers and images running on our machine.

Installing the Docker Desktop also installs the Docker engine and the Docker CLI available with the `docker` command.

When starting the Docker Desktop, it automatically starts the Docker engine.  
We can tick a box in the settings to start Docker engine when we login on our machine. 


## Docker Images

A Docker image is a blueprint from which containers can be generated.  
It packages all data and configuration to start a specific container.  

An image is created once, and its content can not be changed (read-only).  
To update anything in the image (for example when the source code of the app changed), a new image must be built.  

The image is what is shared across developers of a team.  
Each developer can start locally some containers using this image.

Popular images are available on Docker Hub (alpine, nginx, node, python...).  
They can be retrieved locally with the `docker pull <image>` command.

A common use case is to create a custom image based on a popular image that is enriched.  
For example to run a Node.js web server, an image can be created from the `node` image, and enriched with the custom Node.js app code and configuration files.  
Custom images are built using a Dockerfile with the `docker build` command.


# Docker Containers

Using the Docker CLI, containers can be listed, started, stopped and removed.

A Docker container is started from an image with the `docker run <image>` command.  
It runs independently of the host machine and other containers.  
For example multiple containers can run a web server on port 80, as this port is only visible from inside the container.  

To expose a port from inside the container to the host machine, a port mapping must be explicitly published.  
It maps a port on the host machine to a port inside the container.  
For example to map port 3000 on the host to port 80 inside the container : `docker run -p 3000:80 myimage`  
Requests on port 3000 on the host would then be forwarded to port 80 inside the container.

Only one container can map to a specific port of the host.  
If 2 containers expose their port 80, we can map one to port 3000 of the host and one to port 3001 of the host for example.

By default, `docker run` run a container in attached mode, so we can see its output, but we cannot interact with it.  
If the execution requires user input in the terminal (for example with `input()` in Python) we can run it in interactive mode with the `-it` parameter : 
```commandline
docker run -it my-python-image
```


## Docker Hub

Docker Hub is the official registry for Docker images, where all popular images are stored and documented.  
Anyone can store Docker images on Docker Hub, and users can download/use/rate them.  
Multiple images can be organized in a repository and have a different name (tag).

For example, the `node` image contains all dependencies required to start a Node.js application.  
We can download it with `docker pull node` and start some containers based on it.

To share an image with someone we can either :
- share the source code and the `Dockerfile`, so other people can build the same image themselves
- share the already built image on Docker Hub, so other people can download it 

An image can be uploaded either to Docker Hub or to any private image registry.  
Docker Hub offers unlimited public repos and one free private repo (premium account required for multiple private repos).

To push an image to Docker Hub, create a Docker Hub account, then create a repository.  
One repository will contain all images for the same app on different versions.  

Then from the CLI, we need to login to Docker with the `docker login` command.  
This will allow us to push to Docker Hub and to pull private images.

Once logged in, an image can be pushed to Docker Hub with : 
```commandline
docker push <DOCKER_USER_NAME>/<REPO_NAME>:<TAG>
```

The local image name must match the repository name on Docker Hub.  
If needed we can rename a local image with the `docker tag` command.

When we push an image to Docker Hub, it is smart enough to only push the new layers.  
For example if an image is based from the `node` image, the layers of the `node` image will not be pushed.


### Docker CLI 

#### Generic commands

```commandline
docker -v                      // Docker version
docker --help                  // All docker commands can use --help to show options

docker login                   // login to Docker Hub
docker logout                  // logout from Docker Hub
```

#### Images

Images can be listed, pulled from the Docker Hub, built locally and removed.  
Images can have a name and a tag, for example `node:14` so multiple images can have the same name with different tags.

```commandline
docker images                                  // list all images stored locally

docker pull <IMAGE_NAME>                       // download an image from Docker Hub
docker build .                                 // create an image from a Dockerfile
                                               // -t name[:tag]  to assign a name and optionally a tag to the image
                                               // -f <DOCKERFILE_PATH> to specify a custom Dockerfile
                                               // --target <STAGE_NAME> build up to the specified stage (for multi-stage Dockerfile)

docker rmi <IMAGE_ID>                          // delete an image
docker image prune                             // remove all unused images

docker image inspect <IMAGE_ID>                // inspect the content and config of an image

docker tag old_name:old_tag new_name:new_tag   // rename an image (both image name and tag)

docker push <REPO>/<IMAGE>:<TAG>               // push an image to Docker Hub or a private registry
```

#### Containers

Containers can be listed, started, stopped and removed. 

```commandline
docker ps                             // list running container (synonym : docker container ls)
                                      // -a to include exited containers

docker search <KEYWORD>               // look for containers with the keyword on Docker Hub

docker stop <CONTAINER_ID>            // stop a running container
docker start <CONTAINER_ID>           // start a stopped container (in detached mode by default)
                                      // -a to start the container in attached mode
docker attach <CONTAINER_ID>          // attach to a container running in detached mode

docker rm <CONTAINER_ID>              // delete a stopped container
docker container prune                // delete all stopped containers

docker run <IMAGE_NAME>               // run a container from an image (download it if not available locally)
                                      // --name <NAME>    : assign a name to the container
                                      // -d               : run in detached mode (in the background)
                                      // -p 8081:8080     : bind port 8081 on host to 8080 in the container
                                      // -it              : run in interactive mode (for example Node.js terminal for "node")
                                      // -rm              : delete the container when it is stopped
                                      // -e AAA=aaa       : create env variable AAA equal to "aaa"
                                      // --network <NAME> : start the container inside an existing network
                                      // -v <NAME>:<DIR>  : create a named volume in the container
                                      // -v <DIR>         : create an anonymous volume in the container
                                      // -v <DIR1>:<DIR2> : create a bind mount between DIR1 on host and DIR2 in the container 
                                         

docker exec -it <CONTAINER_ID> bash      // open a shell inside a running container
docker cp <FILE> <CONTAINER_ID>:<PATH>   // copy a file from the host machine to inside a container

docker logs <CONTAINER_ID>            // show the logs printed by a container
                                      // -f to follow the log output
```


### Docker Volumes

Images are read-only layered file systems (one layer per instruction in the Dockerfile).  
Since images are read-only, their FS is shared across all containers using them.

A container is using the read-only layered file system from the image, and creates above it a read-write container layer.  
If multiple containers run the same image, there will be no code duplication, just a read-write layer created for each container above the same read-only file system from the image.  
A container's read-write layer is destroyed when the container is destroyed.

To have some persisting data, we can use Docker volumes to give the container access to a persisted folder in the host machine.

The 3 ways to store data when running a container are :
- stored in the image : read-only data in the image layers, shared by all containers using the image (source code, binaries, dependencies...)
- stored in the container layer : temporary data destroyed when the container is removed (in-memory, temporary files...)
- stored in a volume : permanent application data persisted even after the container is removed (database, log files...)

A Docker volume is a folder of the host machine that is mounted (made available) in the container.  
When the container is removed, the data in the volume are persisted on the host machine.  
That means that we can start another container later and re-use this volume.

Docker volumes are not supposed to be accessed from the host machine, and Docker does not expose where they are actually stored.  
They should be used only by the containers.

Docker has 3 types of volumes : Anonymous Volumes, Named Volumes and Bind Mounts.


### Named Volumes

Named volumes are referenced by a name when they are mounted to a container.  
They are managed by Docker, and we do not know where they are stored on the FS of the host machine.  
All we know is that when we mount a named volume to a container, it will always be mapped to the same folder in the host.  

They are not deleted after a container shuts down, so the next instance of the container can re-use it.  
Named volumes can be accessed by multiple containers, so it also allows shared data between containers.

To mount a named volume to a container, we use a name prefix with the `-v` volume parameter :
```commandline
docker run -d -p 3000:80 --name my_container -v my_volume:/app/persisted my_image
```

Named volumes are listed with the `docker volume ls` command.

Details on a volume (creation time, read-only...) can be displayed for a given volume with :
```commandline
docker volume inspect my_volume
```


### Bind Mounts

While anonymous and named volumes are managed by Docker, bind mounts are managed by the user.  
The user explicitly maps a folder from the host machine to a folder inside the container layer.  
That is especially useful during development, we can use a bind mount for the folder containing the app source code.  
This allows the app to pick up the code changes without rebuilding the image.  

A bind mount is also specified when running a container, with a syntax similar to named volumes.  
Instead of a volume name, we prefix the path in the container by the absolute path of a folder on the host.
```commandline
docker run -d -p 3000:80 --name my_container -v /Users/bob/dev/myproject:/app my_image
```

Bind Mounts are not listed with the `docker volume ls` command.  
They are only a connexion between a specific folder in the host and in the container.

### Anonymous Volumes

An anonymous volume is managed by Docker and its folder on the host machine is not exposed.  
It is linked to a specific container, and its name is decided by Docker.  

An anonymous volume can be specified in the image definition with the `VOLUME` instruction in the Dockerfile.  
It takes an array of paths inside the container that should be mapped to a volume when starting the container.

Anonymous volumes are listed with `docker volume ls` and are assigned a random name.

Anonymous volumes are not deleted when their container is removed, but they cannot be reused by a later container.

They are used in special cases, to specify a different behavior in a folder and in one of its sub-folders.

We may want to use a bind mount, but have a sub-folder of this bind mount be managed by Docker.  
For example, we want the `/app` folder to use a bind mount to the source code in the host, but we want `/app/node_modules` to be managed by Docker and populated in the image.  
In that case, we can create a bind mount to `/app`, and an anonymous volume for the `/app/node_modules` folder.  
The anonymous volume on `/app/node_modules` has a deeper path, so it has priority over the bind mount on `/app`.  

### Read-Only Volumes

A named volume or a bind mount can be attached as read-only to a container by adding the `:ro` suffix.  
This can for example be used to prevent the container to modify the content of a bind mount containing the source code.  
```commandline
docker run --name my_container -p 3000:80 -v /my/source/code:/app:ro my_image
```

If we want a single sub-folder of this source code to be writable, we can use an anonymous volume for the sub-folder.  
The anonymous volume has a deeper path than the bind mount, so this sub-folder only will be managed by Docker and be writable :
```commandline
docker run --name my_container -p 3000:80 -v /my/source/code:/app:ro -v /app/temp my_image
```


## Dockerfile

A real-life application development pipeline may look like :
- source code is pushed to the git repo
- the code is compiled and tested
- a new Docker image is created
- the Docker image is stored in a private repository (like AWS ECR)

The Docker image creation is done with the `docker build` command and uses a Dockerfile :
```commandline
docker build -t myapp:v1 .		// -t for image name and tag
```

The Dockerfile is the sequence of instructions to build an image.  
The image needs to contain all the files used to run the application (jar, war, bundle.js).  
Once the image is created, it can be used to start a container of pushed to Docker Hub or any other image registry.

A Dockerfile is a sequence of instructions written in a Docker specific language.  
Docker images are layered : each instruction in the Dockerfile creates an additional layer for the image.  
When building an image, Docker caches the state after each layer, and only applies the instruction if anything changed.  
If a layer needs to be rebuilt, all later layers are also rebuilt.

When a container starts, it uses all read-only layers from its image, and an additional read-write layer specific to this container.

Main instructions in a Dockerfile :

```commandline
FROM <image_name>              // docker image to build upon, take it from Docker Hub if not locally available
LABEL <key>="<value>"          // add metadata to the image (version, maintainer, ...)
EXPOSE <port>                  // port used inside the container intended to be exposed to the host machine
                               // this is only informative, ports still needs to be binded with -p in "docker run"
ENV <name>=<value>             // define an environment variable inside the image and default it
ARG <name>=<value>             // define a build-time argument usable in the Dockerfile and default it
WORKDIR <dir>                  // working directory in the image from where the COPY, RUN, and CMD commands will run
RUN <unix command>             // command executed inside the image in the read-write layer
                               // used to install packages, there can be multiple RUN instructions in a Dockerfile
COPY <host_dir> <image_dir>    // copy a folder from the host machine to inside the image
CMD <unix command or params>   // default command run when starting a container with this image
                               // can be overriden with another command with "docker run <image> <other cmd>"
                               // only one CMD instruction is allowed in a Dockerfile
                               // can be either a unix command (CMD npm start) or a list of values (CMD ["npm", "start"])
ENTRYPOINT <unix command>      // entrypoint command at container startup
                               // can not be overriden, but add the params in CMD at the end (to customize the command)
                               // only one ENTRYPOINT instruction allowed in a Dockerfile
VOLUME [<volume_paths>]        // specify all folders inside the container that should be mapped to a volume at container startup
```

At least one of `CMD` and `ENTRYPOINT` must be specified :
- `CMD` is used for a default command at container launch time that can be overriden
- `ENTRYPOINT` is used for a non-overridable command to which the `CMD` parameters are appended if any.

To prevent the copy of some specific files from the host to the container with the `COPY` instruction, we can create a `.dockerignore` file.  
It must be in the same folder as the Dockerfile, and list files to ignore (Dockerfile, npm_modules, .git folder ...).

Once an image is built, it can be pushed to Docker Hub.  
This requires to have a Docker Hub account, and to have created in Docker Hub a repository for this image.
```commandline
docker login
docker push <DOCKER_HUB_NAME>/<IMAGE_NAME>
```


#### Example Dockerfile for a Node web server

```commandline
FROM node:alpine                      -> image used as a base to built upon (alpine is a very light version of linux)
LABEL version="1.0"                   -> give a version to the image
WORKDIR /var/www                      -> set the working directory in the container
COPY package.json .                   -> copy package.json to /var/www
RUN npm install                       -> command executed inside the container when building the image
COPY . .                              -> copy the /var/www folder in the host machine to inside the image
                                      -> done after the "npm install" layer to not recreate the dependencies at each code change
EXPOSE 8080                           -> port exposed to the outside
ENTRYPOINT ["node", "server.js"]      -> command run at container startup
```


## Environment Variables and Build-time Arguments


### Environment Variables

Environment variables are variables needed at runtime by the application running in the container.

They can be declared and defaulted in the Dockerfile with the `ENV` instruction : `ENV PORT=80`  
They can also be set when running a container with `--env PORT=8000` (or the `-e` shortcut) or `--env-file .env` to use a file.

They are accessible inside the container and can be used by the application code.  
They can also be referenced inside the Dockerfile with a $ prefix : `EXPOSE $PORT`


### Build-time arguments

Build-time arguments are variables needed by the Dockerfile to build the image.  
They can only be used within the Dockerfile, and not in the `CMD` instruction that is executed at runtime.

They can be used to generate multiple images (dev and prod for example) from the same Dockerfile by simply changing the argument value.

They can be declared in the Dockerfile with the `ARG` instruction :  `ARG DEFAULT_PORT=80`  

They are used inside the Docker file with the same syntax as env variables using a $ prefix : `ENV PORT=$DEFAULT_PORT`

They can be set when building an image with `--build-arg DEFAULT_PORT=8000` in the `docker build` parameters.
 

## Popular Docker Images on Docker Hub

| Image         | Description                                                                                  |
|---------------|----------------------------------------------------------------------------------------------|
| ubuntu        | Official OS for Ubuntu, used as based to many images                                         |
| alpine        | Less user friendly but lighter Linux distribution                                            |
| nginx         | Web and reverse-proxy server, used to serve a JS/HTML website (React or Angular for example) |
| mysql         | MySQL relational database server                                                             |
| postgres      | PostgreSQL relational database server                                                        |
| redis         | Redis in-memory database                                                                     |
| mongo         | MongoDB noSQL database                                                                       |
| mongo-express | MongoDB web admin console                                                                    |
| node          | Node server, used as base for Node-based applications (Express, Angular, React...)           |
| php           | Base image for PHP projects                                                                  |
| python        | Base for projects running Python                                                             |
| bitnami/kafka | All binaries to start a Kafka cluster and producers or consumers                             |
| busybox       | Collection of common Unix utilities with limited features, used in embedded systems          |
| wordpress     | WordPress content management system                                                          |


## Docker Networking

Networking is required when a container needs to communicate with the outside :
- on the internet : for example to reach an online REST API
- on the host machine : for example a MongoDB server running on localhost
- in another container : for example a database running in another Docker container
 
By default, containers can access the Internet, so HTTP requests to online REST APIs work from inside a container.

By default, containers cannot reach the host with the `localhost` host name.  
Instead they should use `host.docker.internal` that references the host where the container is running and is available from inside containers.

For inter-container communication, we can create a Docker network.   
Each container can specify a network inside which it is running (one at most).  
Multiple containers can run inside the same network.  
All containers running inside the same Docker network can communicate with each other using their container name.

Docker networks need to be created before being referenced (they are not created on the fly like named volumes).
```commandline
docker network create my_network    // create a Docker network
docker network ls                   // list all networks
docker network inspect my_network   // show network configuration and containers
```

A container can specify its network with the `--network my_network` parameter in the `docker run` command.

> **Docker Network Example**  
A container named `my_mongo` is running in the `my_network` network a MongoDB server.  
It does not expose its 27017 port to the host machine.  
Another container called `my_backend` runs in the same network.  
It can connect to the MongoDB server with URL `mongodb://my_mongo:27017/my_database`


Docker networks can specify their driver with the `--driver` parameter, which defines what type of communication the network allows :
- `bridge` : allow containers on a single host to communicate with each other using container names (default)
- `host` : allow containers to bypass container network isolation and share the localhost with their host machine
- `overlay` : allow containers across multiple hosts to communicate with each other
- `none` : no network connectivity, so no communication with other containers or the internet

We can create a network with the `--internal` parameter to allow containers to communicate with each other but prevent internet access. 


## Example of multi-container MERN webapp

A containerized MERN webapp can consist of 4 containers :
- a MongoDB database server
- a MongoDB console to monitor the MongoDB database
- a Node.js Express backend
- a React frontend

First we create a network for the backend container to access the MongoDB container :
```commandline
docker network create mern_network
```

Then we start the MongoDB container using the public `mongo` image.  
No port needs to be exposed because only the frontend container and the MongoDB console container will access it, and they will share a network.  
To have data persistence even after MongoDB container is removed, we store its data in a named volume.  
We use environment variables for authentication (user and password).
```commandline
docker run -d --rm --name mern_mongodb
                   --network mern_network
                   -v mern_mongodb_data:/data/db
                   -e MONGO_INITDB_ROOT_USERNAME=admin
                   -e MONGO_INITDB_ROOT_PASSWORD=password
                   mongo
```

We can then start a `mongo-express` container and expose its port 8081.  
It connects to the MongoDB database and offers a web GUI to monitor its content at [http://localhost:8081/](). 
```commandline
docker run -d --rm --name mern_mongodb_gui
                   --network mern_network
                   -e ME_CONFIG_MONGODB_SERVER=mern_mongodb
                   -e ME_CONFIG_MONGODB_ADMINUSERNAME=admin
                   -e ME_CONFIG_MONGODB_ADMINPASSWORD=password
                   -p 8081:8081
                   mongo-express
```

Build the backend image from the code using a Dockerfile :
```commandline
docker build -t mern_backend_img:v1 .
```

Run the backend image from the created `mern_backend_img:v1` image.  
It must run in the same network as the MongoDB image.  
The app connects to the MongoDB server by its container name using URL : `admin:password@mern_mongodb:27017/db_name?authSource=admin`  
It must expose port 80 for the frontend running in a browser to reach it.  
Logs are bound to a named volume to persist them after container removal.  
MongoDB credentials are passed as environment variables and used dynamically in the MongoDB URL.

```commandline
docker run -d --rm --name mern_backend
                   --network mern_network
                   -p 80:80
                   -v mern_backend_logs:/app/logs
                   -e MONGO_INITDB_ROOT_USERNAME=admin
                   -e MONGO_INITDB_ROOT_PASSWORD=password
                   mern_backend_img:v1
```

In a development environment, we could instead use a bind mount for the source code folder, and use `nodemon` as a start command to have the app restart on code change.    
The `node_modules` folder should then use an anonymous volume, so it is not copied from the host machine.  
Note that on Windows, the folder referenced by a bind mount should be inside the WSL2 Unix environment.

```commandline
docker run -d --rm --name mern_backend
                   --network mern_network
                   -p 80:80
                   -v mern_backend_logs:/app/logs 
                   -v <code_folder>:/app
                   -v /app/node_modules
                   -e MONGO_INITDB_ROOT_USERNAME=admin
                   -e MONGO_INITDB_ROOT_PASSWORD=password
                   mern_backend_img:v1
```

Create the image for the frontend project from a Node-based Dockerfile, exposing port 3000 and using `npm start` to start the web server.
```commandline
docker build -t mern_frontend_img:v1 .
```

Start the frontend container using this image.  
It needs to use the `-it` flag to run in iterative mode (constraint of React projects) so the app starts correctly.  
It does not need to be part of the network, since the code runs in the browser, so it accesses the backend server publicly.  
It needs to expose port 3000 to make the frontend code accessible from a browser.  
We could also use a bind mount for the source code during development to restart the server on code change.
```commandline
docker run -d --rm -it --name mern_frontend
                       -p 3000:3000
                       mern_frontend_img:v1
```

Confirm that the frontend is now accessible at URL http://localhost:3000 and that it can reach the backend correctly.


## Docker-Compose

Docker-Compose is a tool that helps with the management of multi-container applications.  
It uses a single `docker-compose.yml` configuration file that contains definitions of services, networks, volumes...  
Starting of stopping all containers of the app can then be done by a single command.  

The `docker-compose.yml` file describes services, that correspond to containers in the application.  
Each service has some properties : an image, published ports, env vars, network, volumes...  
These properties are translated by Docker-Compose into parameters for the underlying `docker run` commands.

By default, Docker-Compose creates a network shared by all containers of the file.

The exhaustive list of properties that can be set in the file are detailed on the [official Docker-Compose documentation](https://docs.docker.com/compose/compose-file/).   
A Docker-Compose `version` field (3.8 at time of writing) must be specified.  
It also takes a `services` field that lists all services that are part of the application.  
Each service is given a name, and specifies its properties : `image`, `ports`, `volumes`, `environment` ...    
If the image needs to be built, we can use the `build` field with the relative path to the folder containing the Dockerfile.

The `--rm` flag does not need to be specified since it is the default behavior when using Docker-Compose.  
The `-d` flag is not specified in this file either, it can be specified when launching the application.  
The `-it` flag is replaced by fields `stdin_open` and `tty` both set to `true` in the container properties.

All named volumes that Docker should create must be listed in a `volumes` field at the top-level. 

We can enforce an order to create the containers by using the `depends_on` field for specific containers.

By default, each container will have an auto-generated name of the form `<FOLDER_NAME>_<SERVICE_NAME>_<NUMBER>`.  
This can be overriden with the `container_name` property in a service configuration.

Docker-Compose commands are executed with the `docker-compose` executable :

```commandline
docker-compose build            // build services into images
docker-compose up               // create images, then create and start the containers
                                // -d to start in detached mode
                                // --build to force the re-build of images
                                // <NAME_1> <NAME_2>... to only start specific services
docker-compose down             // stop and remove the containers
                                // -v to also removed the attached volumes
docker-compose run <NAME> <CMD> // run a single service and optionally give it a command                            
docker-compose logs
docker-compose ps
docker-compose start
docker-compose stop
```

### MERN webapp example 

##### docker-compose.yml
```commandline
version: '3.8'
services:

  mongodb:
    image: 'mongo'
    volumes:
      - mongodb_data:/data/db
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=password

  backend:
    build: ./backend
    ports:
      - 80:80
    volumes:
      - backend_logs:/app/logs
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=password
    depends_on:
      - mongodb

  frontend:
    build: ./frontend
    ports:
      - 3000:3000
    stdin_open: true
    tty: true
    depends_on:
      - backend

volumes: 
  mongodb_data:
  backend_logs:
```


## Docker Deployment

To deploy a containerized application, its containers must run on non-local machines.

There are a few differences between development and production environments :
- bind mounts are useful in development but should not be used in production
- some applications (like React) need a special build step for production
- some multi-containers projects may need to split the containers across multiple hosts
- in production, we may want to go for a managed solution (for the DB, or for the containers management)


### Deployment to a Remote Host (AWS EC2)

A remote host can be setup on the cloud with Docker installed on it.    
Containers can be started on this host, pulling the application images from an image registry (Docker Hub or AWS ECR).  
We can choose any Docker-supporting hosting providers, like AWS, Azure or GCP.

For example, to start a mono-container Node webapp on AWS EC2 :  

- create a repository in Docker Hub for the image, then create the image locally and push it to Docker Hub :
```
docker build -t <DOCKER_USERNAME>/<IMAGE_NAME> .
docker login
docker push <DOCKER_USERNAME>/<IMAGE_NAME>
```
- from an AWS account, start a `t2.micro` EC2 instance with Amazon Linux AMI, using a security group allowing traffic to port 20 (SSH) and 80 (HTTP)
- connect to that EC2 instance, either with a web shell (Connect > EC2 Instance Connect > Connect) or via SSH : 
```commandline
# the private key file is generated when starting the EC2 instance
chmod 400 <PEM private key>
ssh -i "<PEM private key>" ec2-user@<EC2 instance public IP>
```
- install Docker on the remote host :
```commandline
sudo yum update -y
sudo yum install -y docker
sudo service docker start
sudo usermod -aG docker ec2-user   # on new terminal, avoid to use "sudo" for docker command
sudo systemctl enable docker       # make docker service auto-launch at startup
docker version                     # will work without the "sudo" only in a new terminal
```
- launch the Docker container on this EC2 instance (no need to login if the image is public) :
```commandline
docker pull <DOCKER_USERNAME>/<IMAGE_NAME>
docker run -d --name <CONTAINER_NAME> -p 80:80 <DOCKER_USERNAME>/<IMAGE_NAME>
```
- Ensure that the webapp is accessible from a browser using the public IP of the EC2 instance.

To update the app, we would push a new image to Docker Hub, pull this updated image in the EC2 instance, then stop and re-run the container.

This approach works well and offers full control over the remote host, but implies to manage ourselves the EC2 instance running the webapp.  
We are responsible for the creation of the EC2 instance, its configuration (adding Docker), its scaling if traffic changes, its security... 


### Deployment to a managed container service (AWS ECS)

A managed service helps with the deployment and monitoring of containerized apps on the cloud.  
Most cloud providers offer this kind of managed service, in AWS it is the ECS service (Elastic Container Service).  
The creation, management, update, scaling and security of the underlying remote host are handled by the managed service.

With a managed service, we no longer call Docker directly, instead we use the commands provided by the service.  
The managed service then executes the Docker commands behind the hood.

Just like the deployment to an EC2 instance, application images must be pushed to an image registry (Docker Hub or AWS ECR).  

In AWS ECS, we can create a **container** with a custom image from the image registry.  
We can specify the ports to publish, the working directory, the environment variables, the command override...    
This configuration will be use by ECS when executing the `docker run` command.  
We can also specify to use CloudWatch logs to store the container logs.  
A container can specify mount points (Docker volumes) to a given path inside the container, from those defined in the task (using EFS).

A **task** in ECS is the configuration of a remote host, that can contain one or more running container(s).  
It corresponds to the EC2 instance in the remote host deployment.  
It can be setup to use Fargate (serverless containers on the cloud) or EC2 (underlying EC2 machines).  
Note that all containers within a same task are guaranteed to run on the same machine.  
Containers cannot use another container's name to communicate with each others (as they can in local development), but ECS allows them to use `localhost`.  
Tasks can specify volumes of type EFS (Elastic File System) for data persistence (it needs inbound NFS traffic allowed in its security group).  
Within a task, all containers must expose different ports, if multiple containers need to expose port 80 for example they should be running in different tasks.

A **service** in ECS is a layer above a task that define how many instances of this task should run, and it  handles load balancing.  
It can be setup to use Fargate or EC2, and can use an application load-balancer for load-balancing and domain-name assignment.  
When using a load balancer, we need to specify a security group and a URL to ping for continuous health check.
  

A **cluster** in ECS is the network in which our services run, all services of an app are part of the same cluster.

Once all of these are configured, we can launch the cluster to deploy the app in ECS.

To update the app, we can push new versions of the custom images to the image registry.  
In the task definition, we can click "Create New Revision", then "Create", forcing ECS to pull the latest image.


### Database Deployment

For a production environment, it can be preferable to use a managed database solution instead of deploying ourselves a database container.  
For example, an SQL database can use AWS RDS, or a Mongo database can use Mongo Atlas.  
This managed solution would handle the availability, scalability, backup, update and security of our database.

In that case, we must decide if the development environment would still use a local database, or also use the managed database solution.  
Using a local database container for development provides more isolation.  
Using the managed solution (with a different DB name for example) offers a development environment closer to the actual production environment, especially regarding the connection to the database and the database version.


### Multi-Stage deployment

Some containers need to be built differently for development and production.  

A typical example is frontend containers like Angular and React.  
For development, they use the `npm start` command that build debuggable non-optimized JS/HTML frontend code, creates a local development server and serves the frontend code.  
For production, the `npm build` command must be run to generate optimized frontend code.  
No web server is created for production, we need to serve the built frontend code with an external web server.  
The most common choice is NGINX.

This can be done with a different Dockerfile for production.  
This Dockerfile can be multi-stage, which means it includes multiple `FROM` instructions.  
Each `FROM` instruction creates a stage that can copy code from previous stages.  

In an Angular or React application, it means we can have : 
- a first stage using ` FROM node` to build the production frontend code
- a second stage using `FROM nginx` copying the production code from the previous stage to the folder that NGINX serves

##### Dockerfile.prod
```commandline
# build stage to generate production code  
FROM    node:14-alpine as build_stage
WORKDIR /app
COPY    package.json .
RUN     npm install
COPY    . .
RUN     npm run build

# deploy stage to start a web server serving production code
FROM    nginx:stable-alpine
COPY    --from=build_stage /app/build /usr/share/nginx/html
EXPOSE  80
CMD     ["nginx", "-g", "daemon off;"]
```



## Kubernetes (K8s)

Kubernetes is an orchestration framework for microservices applications running on containers.  
It was developed by Google, inspired from Borg and Omega, and given to the open-source community.

Some problems that Kubernetes help to solve are :
- monitoring and replacement of containers when they go down
- run more of less container instances to adapt to traffic spikes
- equal distribution of traffic across all instances of a container

Managed services like AWS ECS address these problems by offering health checks, automatic container deployment, auto-scaling and load balancing.  
They are a good solution, but it locks the app in the AWS ecosystem by configuring the app according to AWS ECS requirements.  

Kubernetes is an alternative to AWS ECS that is independent of any cloud service, and that became the standard for container orchestration.  
It can be thought as a kind of Docker-Compose for multiple machines.  
The architecture of the containers deployment is specified in Kubernetes resource files, that can be used with any cloud provider.  
This config file may be extended with cloud provider specific properties, but overall the same files are used on any provider.  


### Kubernetes Architecture

A **pod** is the atomic unit of scheduling in Kubernetes.  
A container running in Kubernetes is always inside a pod.  
It is possible to have several containers in one pod if they are tightly coupled (sharing memory, volumes...).  

A **worker node** corresponds to a machine that can run some containers (for example an EC2 instance).  
Every pod in a Kubernetes deployment belongs to one and only one worker node.  
A worker node can contain multiple pods.  
A worker node must have Docker installed on it.  
A worker node has a **kubelet**, an agent process responsible for communication between the master node and the worker node.  
A worker node contains a **kube-proxy** that controls the network traffic between pods within the worker node and with the outside.  
Kubernetes can distribute pods evenly across worker nodes when scaling up or down.  

The **master node** is the orchestrator of the Kubernetes cluster.  
It contains the **API Server**, the service in charge of communication with the kubelet of each worker node.  
It also contains the **scheduler**, watching for new pods and selecting which worker nodes to run them on.

The Kubernetes **cluster** is the combination of the master nodes and its worker nodes.


### Kubernetes Local Installation

Kubernetes helps with the orchestration of containers, but it does not create the cluster and the nodes !  
It is part of the Kubernetes installation and configuration process to setup the master and worker nodes.  
The API server needs to be installed on the master node.  
The Kubelet needs to be installed on each worker node.  
Kubernetes will then use them to manage pods on the worker nodes.

If we use AWS for hosting the Kubernetes cluster, it means we should create the EC2 instances, file systems, load balancers...  
Kubernetes will not automatically create all those resources.

Some cloud providers have a managed service that can create resources for a given Kubernetes configuration.  
For example in AWS we can use the AWS EKS managed solution (Elastic Kubernetes service).  
This is a good alternative to AWS ECS when we have a Kubernetes configuration already in place.

A local Kubernetes platform can be easily setup using the **MiniKube** tool.  
It creates a VM on our local machine and starts its cluster on it to simulate another machine.  
It creates a single VM that contains both the master node and a worker node.

First we install the `kubectl` executable to interact with a Kubernetes cluster.  
It can be installed using Homebrew on Mac OS or Chocolatey on Windows : 
```commandline
brew install kubectl                # install kubectl on Mac OS
choco install kubectl               # install kubectl on Windows

kubectl version --client=true       # check the installation
```

We can then install MiniKube : 
```commandline
brew install minikube               # install minikube on Mac OS
choco install minikube              # install minikube on Windows
```

Create the local Kubernetes cluster, including the master node, the worker node and their required software.  
We need to specify the driver that MiniKube can use to create its VM, we can use Docker for that :
```commandline
minikube start --driver=docker         # start the Kubernetes local cluster
minikube status                        # ensure it is running
```

MiniKube exposes a web server showing a dashboard of our local Kubernetes cluster.  
It automatically opens a browser tab on port 52913 of the local machine showing all the Kubernetes cluster info.
```commandline
minikube dashboard
```


### Kubernetes Commands

Kubernetes manages some objects, and creating these objects results in Kubernetes taking actions on the cluster.  
There are different object types that can be created in Kubernetes.

A **pod object** is the smallest unit in Kubernetes, it contains one or more containers (usually one).  
A pod can contain shared resources, like volumes, usable by all containers in the pod.  
A pod has a cluster-internal IP address.  
Containers inside a pod can communicate with each other using the `localhost` address (like in a task in AWS ECS).  
Pods are designed to be ephemeral, they are started, stopped and replaced by Kubernetes.  
Their internal data is lost, except what is saved in a volume.

A **deployment object** is the controller that manages the creation of pod objects.  
Usually we do not manually create pod objects, instead we create a deployment object that handles the pods creation.  
The deployment knows about its target state, and Kubernetes creates required objects to reach that state.  
Deployments can use auto-scaling to adapt to the traffic variation.  

A **service object** can group pods together to expose them to other pods of the cluster, or to the outside of the cluster.  
Pods already have an internal IP address, but it is not visible to the outside, and it changes when the pod is replaced.


#### Imperative Approach

The imperative approach consists in sending commands to `kubectl` to create/delete objects.

We can create a deployment by specifying a deployment name and the Docker image to use.  
This image must come from an image repository (not a local image) since it will be pulled by the worker node running on the VM.
```commandline
kubectl create deployment my-kub-app --image=my_image_repo/my_image
```

We can check that the deployment was created, and it should show as ready if the pod was correctly started from the image.
```commandline
kubectl get deployments
kubectl get pods
minikube dashboard       # show the deployment and pod
```

Create a service exposing the port 8080 in side the pod in that deployment to the outside :
```commandline
kubectl expose deployment my-kub-app --port=8080 --type=LoadBalancer
kubectl get services
```

The service was created, since we use MiniKube it does not have a dedicated IP, but MiniKube provides a URL for it.  
It returns a URL that we can use to access from a browser to the exposed port 8080 from the pod.
```commandline
minikube service my-kub-app
```

We can scale the deployment by setting a number of replicas for our pod :
```commandline
kubectl scale deployment/my-kub-app --replicas=3
```

To update the image in the pod to a new one, we use the command to set an image.  
It specifies the container name and the new image, so we can use the same updated image or an image with another name.  
The container name is visible in the "Pods" dashboard, it is given the name of the original image.  
Note that an image will only be downloaded if it has a different name or tag from the current one.
```commandline
kubectl set image deployment/my-kub-app my_image=my_image_repo/my_new_image
```

We can monitor the status of this rollout to see if the image was updated successfully.  
For example it will show that the rollout failed if the requested image name or tag does not exist.
```commandline
kubectl rollout status deployment/my-kub-app
kubectl rollout history deployment/my-kub-app
```

If the deployment rollout failed, and we want to roll it back, we can run :
```commandline
kubectl rollout undo deployment/my-kub-app                    # rollback last rollout
kubectl rollout undo deployment/my-kub-app --to-revision=1    # rollback to given revision (from kubectl rollout history)
```

Services and deployments can be deleted with :
```commandline
kubectl delete service my-kub-app
kubectl delete deployment my-kub-app
```

#### Declarative approach

The declarative approach to setup a cluster is to Kubernetes what Docker-Compose is to Docker.  
It takes as input a resource definition file, and it creates the specified object.  
This avoids to manually create the deployments and services, and allows version control on the configuration.

An object can be created declaratively from a resource definition file with :
```commandline
kubectl apply -f config.yml
```

We can create a deployment from a resource definition file.  
A deployment can contain multiple pods, but they will all be replicas of the same pod.  
A pod can contain multiple containers.  
Each container defines its image, its environment variables, its volumes...  
By default Kubernetes checks the health of pods and restarts them if they are failed.  
We can customize for each container what endpoint to use for the health check.

###### deployment.yaml 
```commandline
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-kub-deployment
spec:
  replicas: 1
  # to identify existing containers that are part of this deployment
  selector:
    matchLabels:
      app: my-kub-app
      tier: backend
  template:
    metadata:
      labels:
        # can add any key/value labels
        app: my-kub-app
        tier: backend
    spec:
      containers:
        - name: my-kub-container
          image: my_image_repo/my_image
          # environment variables
          env:
            - name: STORY_FOLDER
              value: '/story'
          volumeMounts:
            - mountPath: /app/story
              name: my_volume
          liveness:
            httpGet:
              path: /
              port: 8080
            periodSeconds: 10
            initialDelaySeconds: 5
      volumes:
        # use a volume of type "emptyDir"
        - name: my_volume
          hostPath:
            path: /my/data/folder/on/host
            type: DirectoryOrCreate
```

A service can also be created declaratively from a YAML resource definition file.  
Its selector syntax is a bit simpler than the deployment one, because it is an older API. 

###### service.yaml 
```commandline
apiVersion: v1
kind: Service
metadata:
  name: my-kub-service
spec:
  # to identify existing containers that are part of this service
  selector:
    app: my-kub-app
    tier: backend
  ports:
    - protocol: 'TCP'
      port: 80
      targetPort: 8080
  type: LoadBalancer
```

To update the configuration of the cluster, we can simply modify and re-apply one of the resource definition files.  
Kubernetes will automatically perform the required changes to update the cluster.

Deleting objects imperatively also works for objects created declaratively.  
We can also delete the objects declaratively :
```commandline
kubectl delete -f=deployment.yaml -f=service.yaml
```

If we prefer to have all resources defined in a single file, we can group all definitions in a single file and separate with the `---` separator.


### Kubernetes Volumes

Containers managed by Kubernetes can also use volumes to persist data.

Volumes are defined at pod level, so their lifetime is the lifetime of the pod.  
It means their data is persisted after container stop/failure, but does not persist if the pod is removed.

In Docker, a volume is just a folder on the host machine that containers can access to store data.  
In Kubernetes, volumes are more complex, they support multiple drivers and types.

Kubernetes volumes are created in the `spec` property of the deployment resource definition file.  
Each volume should have a `name`, and a type field with type-specific properties.  
This creates the volume at pod level, so it is usable by containers inside the pod.   
Then in a container definition, we can use `volumeMounts` to link a volume to a folder inside the container (see above _deployment.yaml_ example).   

Volume types specify where the data of the volume is going to be stored.  
There are many options, like `emptyDir`, `hostPath`, `csi`, `nfs`, `awsElasticBlockStore`, `azureFile` ...  

An `emptyDir` volume simply creates a named empty directory in the pod that is used as a volume.  
This is good for pods with a single replica, but if we have multiple replicas, they do not share this volume.  
Each replica has its own instance of the volume locally.  
This can be a problem when we reach a replica with a load balancer and do not see the changes made by other replicas.
```commandline
      volumes:
        - name: my_volume
          emptyDir: {}
```

A `hostPath` volume creates a folder in the host machine (the worker node).  
Similarly to a Docker bind mount, we specify the path of the folder in the host that is used as a volume.  
All pods running on the worker node can share the same volume.  
However, pods running on different worker nodes would not share the same volume. 
```commandline
      volumes:
        - name: my_volume
          hostPath:
            path: /my/data/folder/on/host
            type: DirectoryOrCreate
```

The `csi` volume type (Container Storage Interface) was added recently by the Kubernetes team.  
It is a very flexible type, offering an interface that any storage solution can implement by creating a driver.  
For example, AWS EFS can be used, since there are CSI drivers for AWS EFS.

Kubernetes also supports **persistent volumes (PV)**, which are pod and worker node independent.  
They do not get removed even if the pods are replaced or a worker node is destroyed.  
Persistent volumes are another object type that can be defined in Kubernetes.  
Pods can use **persistent volume claims** to request access to one or more persistent volume(s).  

PVs and PVCs can be created with a resource definition file :

###### host-pv.yaml

```commandline
apiVersion: v1
kind: PersistentVolume
metadata:
  name: host-pv
spec:
  capacity: 
    storage: 1Gi
  volumeMode: Block
  storageClassName: standard
  accessModes:
    - ReadWriteOnce
  # hostPath is a testing-only volume type
  hostPath:
    path: /data
    type: DirectoryOrCreate
```

###### host-pvc.yaml

```commandline
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: host-pvc
spec:
  volumeName: host-pv
  accessModes:
    - ReadWriteOnce
  storageClassName: standard
  resources:
    requests:
      storage: 1Gi
```

For a pod to use this PVC, we need to update the _deployment.yaml_ file.  
The PVC must be declared in the volumes section :
```commandline
      volumes:
        - name: my_volume
          persistentVolumeClaim:
            claimName: host-pvc
```

The `volumeMounts` field of the container is identical to any other type of volume.


### Kubernetes Networking

Containers within a pod can communicate with each other using the `localhost` host.  

For inter-pod communication, the communication uses the services.  
If a service needs to be accessed only from inside the cluster, it can be set to the `ClusterIP` type.  
If it also needs to be exposed to outside the cluster, it can be set to `LoadBalancer` type.  

Both `ClusterIP` and `LoadBalancer` services have a cluster-internal IP, shown by the `kubectl get services` command.  
This address can be used to communicate between containers in different pods.  

To avoid having to manually get the address of any service we need to communicate with, Kubernetes exposes some environment variables in every pod containing the cluster-internal IP of all other services in the cluster.  
These env variables are called `<SERVICE_NAME>_SERVICE_HOST` where `<SERVICE_NAME>` is the capitalized underscore-separated service name.  

An alternative to using the service cluster-internal IP is to use the service domain name.  
Kubernetes uses internally the CoreDNS DNS server to generate a cluster-internal domain name for each service.  
Each service is assigned a domain name automatically, set to `<SERVICE_NAME>.<NAMESPACE>`.  
`<SERVICE_NAME>` is the service name as defined in the resource definition file, and `<NAMESPACE>` is the namespace where the service is defined.  
If no namespace is specified in the service configuration, the `default` namespace is used.  
Namespaces can be listed with the `kubectl get namespaces` command.


### Kubernetes Deployment

Kubernetes needs a configured cluster to run on.  
When installed locally, we use **Minikube** that creates this cluster on a virtual machine (or on Docker).  
In production, we need to configure this cluster with real production machines.

The cluster can be deployed either on a custom data center or using a cloud provider.  
When using a custom data center, Kubernetes needs to be installed and configured manually on each machine.  
With a cloud provider, we can also manage manually the entire cluster (for example using AWS EC2).  
Most cloud providers offer a managed service for Kubernetes, that manages this deployment and configuration for us.  
We simply have to define the cluster architecture, and the managed service creates and configure the machines.

#### Cluster creation on AWS EKS

The managed service for Kubernetes in AWS is **AWS EKS** (Elastic Kubernetes Service).  
It is functionally similar to the AWS ECS managed service, but it is aware of the Kubernetes concepts.  
While ECS uses AWS-specific concepts and configuration, EKS can use the existing Kubernetes resource definition files.

In the EKS section of the AWS console, create a new EKS cluster.  
It needs a name, a Kubernetes version, an IAM Role (can select the "EKS Cluster" template in IAM), a cluster VPC...  
AWS EKS has a CloudFormation template that we can use to create the cluster VPC, detailed [here](https://docs.aws.amazon.com/eks/latest/userguide/creating-a-vpc.html).  
Choose "Public and Private" endpoint access, so that the cluster is accessible from outside, but pod to pod communication stays inside the cluster VPC.  

The `kubectl` command should still be used to interact with our Kubernetes cluster on AWS EKS.  
To configure it to access the AWS EKS cluster (instead of the MiniKube local cluster used so far), we should replace its configuration file under `.kube/config`  
While the AWS EKS cluster is running, the config file can be generated from the AWS CLI :
```commandline
# to get the AWS CLI configured with access keys
aws configure

# update .kube/config to reference a given EKS Kubernetes cluster
aws eks --region <REGION> update-kubeconfig --name <CLUSTER_NAME>
```

Once the cluster is created, we can create some nodes inside the cluster.  
From the cluster page, click the "Compute" tab and click the "Add Node group" button.  
We can configure a node group with a name and IAM role (need EC2 + EKS worker + EKS CNI + EC2 Container Registry RO).  
We configure the EC2 instances that will be launched by AWS EKS (AMI, instance type, disk space).  
We can also configure a scaling policy to create more nodes when the traffic increases.  
Creating this node group will result in EKS creating the EC2 instances and installing required software to be usable by Kubernetes.  

Once the node group is running, we can apply our Kubernetes YAML resource definition files, just like we did in MiniKube :
```commandline
kubectl apply -f=my_resource.yaml
```
Note that services deployed on AWS EKS with LoadBalancer type create a Load Balancer in AWS, and it has a URL listed with `kubectl get services`  
We do not need to run any command like `minikube service xxxx` to get this URL, this was only because MiniKube manages a local cluster.


#### Volumes on AWS EKS

For Volumes, we can use the `csi` type and use the Amazon EFS CSI driver.  
The driver installation is detailed on the driver GitHub page : [https://github.com/kubernetes-sigs/aws-efs-csi-driver]()  
It is installed on the cluster with the `kubectl apply` command.  

On AWS, in the EFS service page, we can create an EFS volume in the same network as the EKS cluster.  
It needs a security group with NFS inbound permission from the EKS cluster IP.  

To use this EFS volume in our Kubernetes configuration files, we must create and apply a few yaml resource description files :

- a storage class for EFS volumes :
```commandline
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: efs-sc
provisioner: efs-csi.aws.com
```

- a persistent volume :
```commandline
apiVersion: v1
kind : PersistentVolume
metadata:
  name: efs-pv
spec:
  capacity:
    storage: 5Gi
  volumeMode: FileSystem
  accessModes:
    - ReadWriteMany
  storageClassName: efs-sc
  csi: 
    driver: efs.csi.aws.com
    volumeHandle: fs-59d14521      # file system ID of the EFS volume in AWS
```

- a persistent volume claim on that volume :
```commandline
apiVersion: v1
kind : PersistentVolumeClaim
metadata:
  name: efs-pvc
spec:
  volumeName: efs-pv
  accessModes:
    - ReadWriteMany
  storageClassName: efs-sc
  resources: 
    requests:
      storage: 5Gi
```

- the deployment can then be updated to declare this volume and mount it to a container :
```commandline
    containers:
      - name: users-api
        image: my_docker_name/my_docker_image
        volumeMounts:
          - name: efs-vol
            mountPath: /app/users
    volumes:
      - name: efs-vol
        persistentVolumeClaim: 
          claimName: efs-pvc
```
