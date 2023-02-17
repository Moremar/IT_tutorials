
# Sample project using Angular


## Pre-requisites

- Clone the repo from github
- Create a Firebase project with a Realtime Database to play the role of the backend
- Fill the Firebase project API key and DB URL in src/environment.dts and src/environment.development.ts


## Run on a local web server

```
$>  cd sampleProject
$>  npm install            // install dependencies locally
$>  ng serve -o            // run the app on http://localhost:4200
```

## Deploy to Firebase hosting and access from the web :

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
