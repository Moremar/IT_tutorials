# Angular Tutorial


## Angular Overview

- JS framework for client-side application (front-end) using re-usable components
- Create a single-page application : one root component contains all children components of every page, and
the routing decides the components to display for the requested page.
- Expressive HTML : HTML templates enriched with structural directives : if, loops, ...
- Use Typescript (super-set of JS with classes and strong typing) for all components, services, directives...
- powerful bi-directional data binding
- modular by design
- built-in back-end integration
- complete rewrite of its predecessor AngularJS

#### Main Angular elements

 - **component**  : main building block of an Angular app, representing a re-usable element (TS + HTML + CSS)
 - **service**    : utility class used across the app by multiple components or other services (TS)
 - **model**      : representation of a type of javascript objects used across the app (TS)
 - **guard**      : code executed before loading a route to validate or resolve data (TS)
 - **directive**  : built-in or custom property we can add to component to enrich their behavior (TS)
 - **module**     : grouping building blocks by functionality (components, services, directives ...)

#### Angular Bootstrap 

An Angular app is a single page application : it serves the `index.html` file for any URL.  
This file includes the `app-root` component that contains the entire app.  
The routing is handled by the Angular Router that dynamically selects the component to load at some
specified locations depending on the requested URL.

Angular comes with an integrated web server started with `ng serve -o`  
The custom code (all the components) are grouped by the Angular CLI into JS bundles.  
These bundles are included at the end of the served `index.html` file.  
The first code to be executed is `main.ts`, that bootstraps the AppModule.  
The AppModule contains a `bootstrap` property equal to `[ AppComponent ]`, so Angular knows that the app
must load this component at startup, and it can then replace it in the `index.html` file.

Angular uses **webpack** to bundle all the app code into JS bundles.  
This is called **HMR** (Hot Module Replacement), the code is automatically re-bundled
and the web server updates the page at every code chage.


## Prerequisites

#### Node

Install Node.js from the Node website.  
This is required for the Node Packet Manager (NPM) used to manage the dependencies of an Angular project.  
Dependencies are listed in the `package.json` file.  
Running the `npm install` command downloads them under a `node_modules` folder.  

#### Angular CLI

Install the Angular CLI with the `npm install @angular/cli -g` command.  
It gives access to the `ng` command to interact with Angular.

#### Typescript

Install Typescript with the `npm install typescript -g` command.  
This installs globally the `tsc` command (TS compiler) to transpile TS into JS.  
Angular automatically converts the TS code to JS, so the browser can interpret it.  
We can manually transpile a TS file with `tsc myfile.ts` and run it with `node myfile.js`

#### Visual Studio Code

Download an IDE that supports Angular, for example Visual Studio Code or WebStorm.  
Visual Studio Code can be downloaded and installed for free from their website.  
From the Welcome page, press `Cmd-Shift-P`, then `Install 'code' command in PATH` to get access to the `code` command.

#### Chrome Developer Tools

When using Chrome to test the Angular app, we cann access the developper tools with F12.  
It offers great debugging tools, including the console, network monitoring, DOM inspector...  
We can also use breakpoints in the TS code thanks to the sourceMaps between JS and TS.

Some optional Chrome extensions are also available :
- **Augury** to show the state of each Angular component of the app
- **Redux DevTools** to debug Redux state and actions


## Create or Start an Angular project

A new empty Angular project can be created from the Angular CLI with `ng new myProject`  
It will generate a working project with all the Angular project files.  
It includes a single module and a single component called from the `main.ts` entry point.  

If we download an existing Angular project, we should download locally its dependencies with `npm install`   
This does not need to be done when creating a new project, as `ng new` does it already.

To start the Angular app on a local web sever, run  `ng serve -o`    
The app can then be open at the URL [http://localhost:4200](http://localhost:4200)

