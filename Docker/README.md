# Docker Tutorial


## Introduction

Docker is a light-weight platform for creating and managing application containers.  
It can run on top of any OS and offers software isolation and portability.  
It solves the problem of "It runs on my machine but not on yours".

A container is a standardized self-contained running unit of software.  
It can include scripts, binaries, and any dependencies needed to run the software.  
A container runs stand-alone, independently of the machine it runs on.

A container can run on any machine that runs Docker, on any OS.  
The same container always behave in the exact same way on any machine it is deployed.

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
- **Docker Hub** : official registry of Docker images
- **Docker Compose** : tool to orchestrate several containers running and interacting together

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

Docker Hub is the official registry of Docker images, where all popular images are stored and documented.  
Anyone can store Docker images on Docker Hub, and users can download/use/rate them.  
Multiple images can be organized in a repository and have a different name (tag).

For example, the `node` image contains all dependencies required to start a Node.js application.  
We can download it with `docker pull node` and start some containers based on it.

To share an image with someone we can either :
- share the source code and the `Dockerfile`, so other people can build the same image themselves
- share the already built image on Docker Hub, so other people can download it 

An image can be uploaded either to Docker Hub or to any private image registry.  
Docker Hub offers unlimited public repos and one private repo.

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
Images can have a name and a tag, for example `node:14` so many images can have the same name with different tags.

```commandline
docker images                                  // list all images stored locally

docker pull <IMAGE_NAME>                       // download an image from Docker Hub
docker build .                                 // create an image from a Dockerfile
                                               // -t name[:tag]  to assign a name and optionally a tag to the image

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
                                      // --name <NAME>    : assign a name to the image
                                      // -d               : run in detached mode (in the background)
                                      // -p 8081:8080     : bind port 8081 on host to 8080 in the container
                                      // -it              : run in interactive mode (for example Node.js terminal for "node")
                                      // -rm              : delete the container when it is stopped
                                      // -e AAA=aaa       : create env variable AAA equal to "aaa"
                                      // --network <NAME> : start the container inside an existing network
                                      // -v <NAME>:<DIR>  : create a named volume in the container 
                                         

docker exec -it <CONTAINER_ID> bash      // open a shell inside the container
docker cp <FILE> <CONTAINER_ID>:<PATH>   // copy a file from the host machine to inside a container

docker logs <CONTAINER_ID>            // show the logs printed by a container
                                      // -f to follow the log output
```


### Docker Volumes

Images are READ ONLY layered file systems (one layer per instruction in the Dockerfile).  
Since images are READ ONLY, their FS is shared across all containers using them.

A container is using the READ ONLY layered file system from the image, and creates above it a WRITE container layer.  
If multiple containers run the same image, there will be no code duplication, just a WRITE layer created for each container above the same READ ONLY file system from the image.  
A container's WRITE layer is destroyed when the container is destroyed.

To have some persisting data, we can use Docker volumes to give the container access to a persisted folder in the host machine.

The 3 ways to store data when running a container are :
- stored in the image : read-only data in the image layers, shared by all containers using the image (code/binaries/dependencies...)
- stored in the container layer : temporary data destroyed when the container is removed (in-memory, temporary files...)
- stored in a volume : permanent application data persisted even after the container is removed (database, files...)

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
Once the image is created, it can be used to start a container of pushed to Docker Hub.

A Dockerfile is a sequence of instructions written in a Docker specific language.  
Docker images are layered : each instruction in the Dockerfile creates an additional layer for the image.  
When building an image, Docker caches the state after each layer, and only applies the instruction if anything changed.  
If a layer needs to be rebuilt, all later layers are also rebuilt.

When a container starts, it uses all READ layers from its image, and an additional WRITE layer specific to this container.

Main instructions in a Dockerfile :

```commandline
FROM <image_name>              // docker image to build upon, take it from DockerHub if not locally available
LABEL <key>="<value>"          // add metadata to the image (version, maintainer, ...)
EXPOSE <port>                  // port used inside the container intended to be exposed to the host machine
                               // this is only informative, ports still needs to be binded with -p in "docker run"
ENV <name>=<value>             // define an environment variable inside the image and default it
ARG <name>=<value>             // define a build-time argument usable in the Dockerfile and default it
WORKDIR <dir>                  // working directory in the image from where the COPY, RUN, and CMD commands will run
RUN <unix command>             // command executed inside the image in the WRITE layer
                               // used to install packages, can have several RUN lines in the Dockerfile
COPY <host_dir> <image_dir>    // copy a folder from the host machine to inside the image
CMD <unix command or params>   // default command run when starting a container with this image
                               // can be overriden with another command with "docker run <image> <other cmd>"
                               // only one CMD line is allowed in a Dockerfile
                               // can be either a unix command (CMD npm start) or a list of values (CMD ["npm", "start"])
ENTRYPOINT <unix command>      // entrypoint command at container startup
                               // can not be overriden, but add the params in CMD at the end (to customize the command)
                               // only one ENTRYPOINT line allowed in a Dockerfile
VOLUME [<volume_paths>]        // specify all folders inside the container that should be mapped to a volume at container startup
```

At least one of `CMD` and `ENTRYPOINT` must be specified :
- `CMD` is used for a default command at container launch time that can be overriden
- `ENTRYPOINT` is used for a non-overridable command to which the `CMD` parameters are appended if any.

To prevent the copy of some specific files from the host to the container with the `COPY` instruction, we can create a `.dockerignore` file.  
It must be in the same folder as the Dockerfile, and list files to ignore (Dockerfile, npm_modules, .git folder ...).

Once an image is built, it can be pushed to Docker Hub with :
```commandline
docker login		   // require account on Docker Hub, will ask for login/pwd/email
docker push <IMAGE>
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

A basic containerized MERN webapp can consist of 3 containers :
- a MongoDB database server
- a Node.js Express backend
- a React frontend

First we create a network for the backend container to access the MongoDB container :
```commandline
docker network create mern_network
```

Then we start the MongoDB container using the public `mongo` image.  
No port needs to be exposed because only the frontend container will access it, and it will share a network.  
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
It uses a single configuration `docker-compose.yml` file that contains definitions of services, networks, volumes...  
Starting of stopping all containers of the app can then be done by a single command.  

The `docker-compose.yml` file describes services, that correspond to containers in the application.  
Each service has some properties : an image, published ports, env vars, network, volumes...  
These properties are translated by Docker-Compose into parameters for the underlying `docker run` commands.

By default, Docker-Compose creates a network shared by all containers of the file.

The `docker-compose.yml` available fields are detailed on the [official Docker-Compose documentation](https://docs.docker.com/compose/compose-file/).   
The file first specifies a Docker-Compose `version` field (3.8 at time of writing).  
It also takes a `services` field that will list all services that are part of the application.  
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
docker-compose build        // build services into images
docker-compose up           // create images, then create and start the containers
                            // -d to start in detached mode
                            // --build to force the re-build of images
docker-compose down         // stop and remove the containers
                            // -v to also removed the attached volumes
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
