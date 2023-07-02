# Sample Kubernetes project

This project is made of 4 webapps interacting with each others :
- a dummy `auth` Node webapp that generates hashed password and tokens
- a dummy `users` Node webapp that exposes signup and login endpoints, calling the `auth` webapp
- a sample `tasks` Node webapp to create and list tasks, requiring an authentication token
- a `frontend` React webapp to display a GUI to create and list tasks
  
## Local setup with Docker-Compose

This app can be ran locally with Docker-Compose :
  docker-compose up -d

With Postman, we can then use the app to login :
    POST http://localhost:8080/signup    { "email": "aaa", "password": "bbb" }
    POST http://localhost:8080/login     { "email": "aaa", "password": "bbb" }

And then to create or list tasks, by using a Bearer Authentication token header :
   POST http://localhost:8000/tasks     { "title": "my_title", "text": "my_text" }
   GET  http://localhost:8000/tasks

## Setup with Kubernetes

The goal is to get this interaction with Kubernetes.

The `auth` API must be reachable from the `users` API and the `tasks` API, but not from outside the cluster.  
The `users` API must be reachable by the `tasks` API and from the outside.  
The `tasks` API must be accessible from the outside.  
The `frontend` webapp must be accessible from the outside and will run on client browser.  

We thus want to configure all APIS in separate pods (so individual deployments) with a dedicated service each.  
The `auth` service will be of type `ClusterIP` so it is reachable only from inside the cluster.  
The `users`, `tasks` and `frontend` services are `LoadBalancer` so they are also reachable from outside the cluster.  


First we need to ensure that MiniKube is running so we have a local Kubernetes cluster.
```commandline
minikube start --driver=docker
```

Then we must ensure that our images is available on Docker Hub :
```commandline
cd auth-api/
docker build -t moremar/kub-network-auth .
docker push moremar/kub-network-auth
cd users-api/
docker build -t moremar/kub-network-users .
docker push moremar/kub-network-users
cd tasks-api/
docker build -t moremar/kub-network-tasks .
docker push moremar/kub-network-tasks
cd frontend-api/
docker build -t moremar/kub-network-frontend .
docker push moremar/kub-network-frontend
```

Then we need to create a deployment and a service for each of the 4 APIs.
All Kubernetes resource description files are stored under the `/kubernetes` folder.
```commandline
cd kubernetes/
kubectl apply -f=auth-deployment.yaml -f=auth-service.yaml
kubectl apply -f=users-deployment.yaml -f=users-service.yaml
kubectl apply -f=tasks-deployment.yaml -f=tasks-service.yaml
kubectl apply -f=frontend-deployment.yaml -f=frontend-service.yaml

minikube service users-service
minikube service tasks-service
minikube service frontend-service
```

## Networking with Kubernetes

The `users` app can access the `auth` app using its service cluster IP.  
This IP can be accessed either with the `AUTH_SERVICE_SERVICE_HOST` env var provided by Kubernetes, or by using `auth-service.default` as a host name (the domain name of the auth service).  

Similarly, the `tasks` service uses the `auth-service.default` domain name to access the auth service.

The `frontend` setup is a bit more tricky.  
We cannot use the tasks internal cluster IP, since the code is executed in the browser (outside of the cluster).  
An elegant way to address this issue is to call instead the same host as the React app, with a specific prefix (`/api/` here).  
Then we can configure the NGINX reverse proxy running the React app to handle those requests.  
We add in the `nginx.conf` a block to pass those requests to the tasks service.  
Since the NGINX server is inside the cluster, it can use the internal domain name :
```commandline
  location /api {
    proxy_pass http://tasks-service.default:8000;
  }
```
