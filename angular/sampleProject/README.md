
# Sample project using Angular

## Project Overview

This project is a sample project using most elements of Angular. 
It provides examples of :

- components / directives
- services
- models
- modules
- forms
- routing
- activation guards, deactivation guards and resolvers
- authentication
- lazily loaded modules
- http request to a backend (Firebase Realtime Database)
- deployment to a static website hosting (Firebase Hosting)

This project does not use Redux for Angular (NgRx), check project sampleProjectRedux for an example of how to use it.

## Pre-requisites

- Clone the repo from GitHub
- Create a Firebase project with a Realtime Database to play the role of the backend
- Fill the Firebase project API key and DB URL in `src/environment.ts` and `src/environment.development.ts`


## Run on a local web server

```
$>  cd sampleProject
$>  npm install            // install dependencies locally
$>  ng serve -o            // run the app on http://localhost:4200
```

## Deploy to public Firebase hosting

```
$>  cd sampleProject
$>  npm install
$>  ng build                         // generate the dist/ folder 
$>  npm install -g firebase-tools    // install firebase CLI
$>  firebase login                   // login to Google account
$>  firebase init                    
          -> choose project
          -> select hosting
          -> set /dist as the source folder
          -> always redirect to index.html
          -> do not overwrite index.html
$>  firebase deploy                   // get the app public URL
```
