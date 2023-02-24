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


## Angular CLI

Angular CLI is the command line interface to assist with Angular app development.  
It is used to develop, build, deploy, and test Angular apps.  

```commandline
ng                          List all available commands
ng v                        Version of Angular / Node / OS
ng <cmd> --help             Help for a specific ng command
ng new projectName          Create an empty Angular project
ng serve -o                 Build the app and start a web server
                            -o to open a browser
                            --port to specify a port (default 4200)
ng g c path/componentName   Generate a new component (HTML + TS + CSS + Test)
                            Can be ran from the project root (no need to specify src/app/)
                            --flat to not create a dedicated folder for that component
ng g g path/guardName       Generate a new guard (TS)
ng g m path/moduleName      Generate a new module (TS)
ng g d path/directiveName   Generate a new directive (TS)
ng test                     Run the tests
ng e2e                      Run the end-to-end tests
ng build                    Build app for deployment into the /dist folder
ng update                   Update the project to latest angular version
ng add <external_lib>       Use NPM to install a lib and run a script to setup the Angular project to use it
```


## Angular Components

### Component Structure

- **TS component class**  
  The main element of the component is its TS class definition, with a `@Component()` decorator.  
  This class specifies all member variables and methods of the component.  
  The methods can be called by the template in response to intercepted events.  
  Both member variables and methods can be used in the template (data-binding, if block, for loops ..).  
  The `@Component()` decorator specifies :
  - `selector` : the tag name to use to include this component in a template, for example `app-header`
  - `templateUrl` : the path to the HTML template file of this component
  - `template` : the inline HTM template of this component (alternative to `templateUrl`)
  - `syleUrls` : an array with the path of the CSS files


- **HTML template**  
  The template is the HTML representation of the component.  
  It can reference properties and methods from the component TS class.    
  Those references are called _data-binding_ and are between `{{ ... }}`  
  The HTML template is usually in a dedicated file, but can also be specified inline in the TS class `@Component()` decorator. 


- **CSS stylesheet**  
  The CSS stylesheet contains the CSS styles to apply to HTML tags in this component.  
  Angular simulates a shadow DOM by applying a specific property to all tags in the same component, for ex `ngcontent-ejo-2`.  
  It adds this property in all CSS selectors of the stylesheet to target only tags in this component.

Every component must be declared in exactly one module.  
It is then available to all components in the same module, and to all components in other modules importing this module.


### Component Lifecycle Hooks

Angular provides some methods that can be implemented to execute some code at different stages of the component's life.

```commandline
ngOnInit              : after the component is initialized (after constructor call) but before rendering
ngOnChanges           : after any input property change (and also when just created)
ngDoCheck             : at every change detection run (very often called)
ngAfterContentInit    : after content (ng-content) has been projected
ngAfterContentChecked : every time the projected content has been checked
ngAfterViewInit       : after the component (and its children) is rendered
ngAfterViewChecked    : every time the view (and children view) has been checked
ngOnDestroy           : just before the component is destroyed
```

For each of these hooks, there is an Angular interface to implement to explicitly use this hook.  
Only `ngOnChanges()` hook takes a parameter with the value of all changed input properties :
```commandline
  ngOnInit() { console.log('Component initialized'); }
  
  ngOnChanges(changes: SimpleChanges) { console.log(changes); }
```

### ng-content

By default, any content included between the opening and closing tags of a custom Angular component is lost.  
To allow a parent component's template to pass some HTML content to a child component, the child component must specify in its HTML where the content must be included by adding the `<ng-content>` tag in its template.

If an element in the content has a local reference, we can access it from the child component TS code by creating a property with the `@ContentChild('myInput')` decorator.

The component content can of course not be accessed before the content is initialized (in `ngOnInit()` for ex).

### Standalone components

Since Angular 14, it is possible to create standalone components that are not declared in any module.  
Directives and pipes can also be standalone.  
The goal is to no longer use modules (like React).  

 - compatible with traditional components declared in a module.
 - must have the `standalone` property set to true in the `@Component` decorator
 - must not be declared in any module
 - can be imported by modules needing it
 - can import modules and standalone components it needs with the `imports` property in the `@Component` decorator

All components of an Angular app can be migrated to be standalone, including the root AppComponent.  
If so, the bootstrap code in `main.ts` must be updated to use :
```commandline
    bootstrapApplication(AppComponent);
```

To setup routing in a fully standalone components Angular app, the root component should import the `RouterModule`.  
In `main.ts`, the `bootstrapApplication()` function should take a 2nd parameter (config object) with the routing module :
```commandline
bootstrapApplication(
    AppComponent,
    { providers : [ importProvidersFrom(AppRoutingModule)] }
);
```

Similarly to lazy-loaded modules, we can load standalone components lazily in a route.  
This only requires to replace the `component` property with `loadComponent` :
```json
    "loadComponent" : import("./about/about.component").then((m) => m.AboutComponent)
```


## Data Binding

- **String Interpolation : TS => HTML**  
  Bind a member variable from the TS class to the HTML template, for example displaying a message in the template.  
  It resolves a TS expression in the text of a component :
    ```html
    <div> {{ title }} </div>
    ```


- **Property Binding : TS => HTML**  
  Bind a member variable from the TS class to a property in the HTML template, for example setting the `disabled` field of a button.  
    ```html
    <div [style.color]="colorField"> XXX </div>
    ```

- **Event binding : HTML => TS**  
  Call a method from the TS class when an event is triggered in the HTML template.  
  If specified, the `$event` parameter contains info on the triggered event (click coordinates, input text, ...)  
    ```html
  <button (click)="onClick()" > XXX </button>

  <input (input)="onInputChange($event)" />
    ```

- **Two-way binding : TS <=> HTML**  
  Bind the property of an HTML element to a member variable in the TS class in both directions.  
  It is often used for `<input/>` tags to update a member variable when the input value changes in the template (user action), and to update the input value when the member variable changes (in code).  
  It requires to import `FormsModule` in `app-module.ts` to get access to the `ngModel` directive.  
    ```html
  <input type="text" [(ngModel)]="myStrVar">
    ```


## Inter-component Communication

### Parent to Child : @Input()

For a parent component to give an object to one of its children, we use custom property binding :  
```html
<app-child-elem [server]="serverObjectInParent">
```

The `server` member variable in the TS class of the child component must be defined with the `@Input()` decorator.  
This tells Angular that this member variable is settable from outside via a property in its HTML tag.  
The name of the property of the HTML tag is by default the same as the TS class member variable name.  
It can be explicitely changed by giving a name in the `@Input()` :
```commandline
@Input('serverObject') server : Server;
```

### Child to Parent : @Output()

A child component can emit an event (with a payload) that can be intercepted by a parent component.  

In the child component TS class, create an `EventEmitter` member variable with the `@Output()` decorator.  
Calling the `emit(obj)` method of this event emitter will generate an event that the parent can intercept.  
Similarly to the `@Input()` decorator, a custom name can be given in the `Output()` decorator to rename the event.  
```commandline
@Output() serverCreated = new EventEmitter<{name: string, content: string}>();
```
The child component TS class can emit an event in any of its methods, for example when a user clicks a button :
```commandline
this.serverCreated.emit({name: 'serverTest', content: 'A server was created'});
```
The parent component can intercept this custom event in its HTML template :
```commandline
<app-child-elem (serverCreated)="onServerCreated($event)">
```
And define in its TS class a method to handle this event :
```commandline
       onServerCreated(serverData: {name: string, content: string}) { ... }
```

### More Complex Communication

`@Input()` and `@Output()` decorators are good for simple communication, but it becomes messy when multiple 
components must react to an event, or when the event must traverse multiple levels in the components hierarchy.

In this case, instead of defining the `EventEmitter` in the child component, we can use a service.  
The service defines an `EventEmitter` or a `Subject` object that can be used by components to emit events.  
Components that need to react to the triggered events can subscribe to that event emitter in the `ngOnInit()` hook.  
This subscription needs to be unsubscribed when the component is destroyed to avoid memory leaks :

```commandline
@Component({
    selector' 'app-parent`,
    templateUrl: './app-parent.component.html,
    styleUrls : ['./app-parent.component.css'] 
})
export class AppParent implements OnInit, OnDestroy {

    mySub : Subscription;

    // inject the service containing the event emitter to subscribe to
    constructor(private serverService : ServerService) {}
    
    ngOnInit() {
        mySub = serverService.serverCreated.subscribe(
          (newServer : Server) { console.log(newServer); }
        );
    }
    
    ngOnDestroy() {
        mySub.unsubscribe();
    }
}
```


## Angular Models

Angular models are standard TS classes with no specific decorator.  
A model file should be named `XXX.model.ts`.  
It represents the structure of the data across the app.  
For example, users in an Angular app can be represented by a `User` model in a `user.model.ts` file.

It is technically not required to use models in Angular, but it helps TS and the IDE's Intellisense with type inference.


## Local References

We can create a local reference on any HTML tag with a `#` in an HTML template :

```html
  <input type="text" class="form-control" #myInput />
```

This tag can then be referenced from anywhere inside the HTML template (but not from the TS code!).  

It can be used with string interpolation : `{{ myInput.value }}`  

It can also be used as a parameter of a method call :

```html
  <button type="button" (click)="onClick(myInput)"> Click </button>
```

The `onClick()` method can then access the input HTML element :

```commandline
  onClick(input: HTMLInputElement) { console.log(input.value); }
```

We can use a local reference instead of a property binding to make the code smaller when the value we bind to (an input usually) is used only from the template.

We can also reference a local reference from the TS code if we create a property with the `@ViewChild()` decorator : 

```commandline
  @ViewChild('myInput') input : ElementRef;
```

The `input` member references the `<input>` tag from the template, which is accessed with its `nativeElement` property :

```commandline
  console.log(input.nativeElement.value);
```

It is a bad design to assign the HTML input value directly from the TS code via the ViewChild element though.    
Instead, 2-ways binding should be preferred for this scenario.


## Angular Services

An Angular service is a TS class that can be accessed from any component or service.  
Typical use cases are logging, data management, HTTP requests to a backend...

A service has no dedicated decorator, but the `@Injectable()` decorator is used to inject other services in its constructor.  
It is required only if the service injects other services or components, but it is a good practice to always add it.

Angular can inject an instance of a service in any component from its constructor.  
There are 2 ways to declare a service so it can be injected by Angular in components and other services :

- Specify the service in the `providers` property of the `@Component()` decorator or one of its ancestors (the module for ex)  
  This informs Angular to provide the SAME instance of the service to all components under that component.  
  If we provide the service in `app.module.ts`, all components of this module will use the same instance of the service.  
  If a component provides a service, it will create a new instance of the service.  
  To use the same instance across all components, it is common to declare it in the module.   
  If the service is provided at module level, it can also be injected in services.  


- Add `{ providedIn: 'root' }` parameter to the `@Injectable()` decorator of the service (Angular 6+)  
  This automatically provides the service at module level (no need to add it in the module manually)   
  This is the preferred method to ensure a single instance of the service is used across the app.

Services can be used for inter-components communication using `Subject` or `BehaviorSubject` emitters.  
This is much simpler than passing around data from component to component with `@Input()` and `@Output()` chains.



















## State Management with Redux

### Redux pattern

The application state contains all non-persistent information required to know what should be displayed (loading, tab selected, sent a file, ...). It can be handled only with services and components, by having a service that publishes 
state changes (with a Subject) and components subscribing to it.  

For bigger applications, having one centralized place to manage the application state makes the code easier to read and maintain.  
Redux can help with this application state management.

Redux is a pattern to manage state via a central immutable JS object called the "store" that is the source of truth for every service/component regarding the application state.

To update the state (for example to add an item in an array displayed with a *ngFor), we cannot modify the store directly.  
We need to dispatch an action that defines how to change the store, with an optional payload.  
This action is processed by a "reducer" that calculates the resulting state, and overwrites the current store with the new store.  
The new store is then received by every component needing it by a subscription.  
Every change of the state creates a new version of the store.  
The store is split into sections (one per part of the app) and components can subscribe to a section of the store.

The Angular wrapper for Redux is called `NgRx` (Angular Redux) and implements the Redux pattern using `rxjs` (Subjects) and offering store Observables that components and services can subscribe to.

### NgRx Installation

```commandline
$>  npm install --save @ngrx/store
$>  npm install --save @ngrx/effects     # optional, for side effects
```

### NgRx Actions

An action class must be defined for each type of change we can do on the store.  
We can group actions in an `xxx.actions.ts` file (`xxx` is the section name, for example `auth`).

Actions must implement the `Action` interface by providing a `type` readonly property.  
Actions can have a payload, represented by one or more member variable(s) with details on the action (for example the object to create when adding an object in the state).  
When processing the action, the reducers will have access to this payload.

```commandline
export class AddIngredientAction implements Action {
  readonly type: string = ADD_INGREDIENT;
  constructor(public payload: Ingredient) {}
}
```

### NgRx Reducers

Reducers are functions that are called by Redux to compute the next store after each dispatched action.  
Redux provides as parameter to the reducer functions the current store and the dispatched action.  
At app startup, Redux dispatches an action of type `@ngrx/store/init` to every reducer.  
We can specify the initial state to use for a section of the store with a default value for the store parameter.  
Reducers can only run synchronous code, they take the current store and an action as input and return the resulting store.

Create a file `xxx.reducer.ts` and define a reducer function.  
The reducer must not modify the original store, it must return a new store (usually using the spread operator) :

```commandline
export function ShoppingListReducer(state = initialState, action: AddIngredientAction) {
  switch (action.type) {
    case ADD_INGREDIENT: {
      return {
        // copy all properties of state into the new object
        ...state,
        // overwrite the properties we want to change
        ingredients: [...state.ingredients, action.payload]
      };
    }
    case OTHER_ACTION:
    {
       ... return another modified version of the store ...
    }
    default: {
      return state;
    }
  }
}
```

### NgRx Store

The full store structure with all its sections can be defined in an `app.reducer.ts` file.  
A top-level reducer map can be created to associate a reducer to each section of the store : 

```commandline
export interface AppState {
  auth: AuthState,
  shoppingList: ShoppingListState
};

export const appReducer: ActionReducerMap<AppState> = {
  auth: authReducer,
  shoppingList: shoppingListReducer
};
```

In `app.module.ts`, we import the `StoreModule` and specify the top-level reducer map :

```commandline
imports: [
  ... other imported modules ...
  StoreModule.forRoot(appReducer)
]
```

With this setup, NgRx creates an application store with the given reducers.  
We can access the store by injecting in a service or component a `Store<AppState>` object.    

We can access the observable for a section of the store with the `select()` method of the injected `Store` object :

```commandline
this.subscription = this.store.select('shoppingList').subscribe(
  (shoppingListStore: ShoppingListState) => {
    this.ingredients = shoppingListStore.ingredients;
  }
);
```

### Dispatch an NgRx Action

An action can be dispatched by any service or component.  
It needs to inject the `Store<AppState>` in its constructor and call its `dispatch()` method.
The dispatched action will automatically be executed by all reducers in the reducer map.

```commandline
this.store.dispatch(new AddIngredientAction(payload));
```

### NgRx Side Effects

The reducers should not contain any side effects, they should only set the state.  
A valid possibility is to have those side effects in a service, that dispatches Redux actions when needed.  
NgRx offers an alternative way to handle side effects (REST calls, local storage management, ...) in the `@ngrx/effect` package.

### NgRx Router Store

NgRx has a mechanism called the Router Store, to automatically dispatch an NgRx action every time a route is loaded.  
This lets us change the state of the app on routing events.  

The router store package is installed with : `npm install --save @ngrx/router-store`

It must be added in the imports of the `app.module.ts` file :  `StoreRouterConnectingModule.forRoot()`

### Redux DevTools

Redux DevTools is a convenient Chrome extension to debug the Redux state of an Angular app.  
This extension shows all dispatched actions, and the state after each of them.
- Download the "Redux DevTools" Chrome extension
- Install the ngrx dev tool package as a dev dependency : `npm install --save-dev @ngrx/store-devtools`
- Import `StoreDevToolsModule` in the `app.module.ts` file :
    ```commandline
    StoreDevToolsModule.instrument({ logOnly: environment.production })
    ```
- Relaunch Chrome and `ng serve`, now we have a "Redux" section in the Chrome dev tools showing dispatched actions.


## Unit tests

The Angular CLI comes with the **Jasmine** test framework and the **Karma** test runner.  
At component creation, the CLI generates a default `xxx.spec` file for unit tests.  
By default it only checks that the component can be created with no error.  

The Karma test runner can be executed with the command :  `ng test`  
The terminal shows `Executed X of X SUCCESS`, and a Jasmine HTML page opens in Chrome with the tests details.  
The `ng test` command is watching for changes, it re-runs the tests at every change.

The main class of the Angular testing module is `TestBed`  
The `beforeEach()` method of the test suite is called before each test run.  
In its body, we call the `configureTestingModule()` and the `compileElements()` functions
to setup the test environment.    
A component fixture is created with the `createComponent()` method and is accessible in each test.

Each unit test is represented by an `it()` function inside the test suite.  
There are generally 2 different types of tests :
- tests checking the behavior of the component (member variables and methods)
- tests checking the HTML output of the component

Behavior tests may need to access some injected services, which are available in the injector :
```commandline
let service = fixture.debugElement.injector.get(UserService);
```

Output tests can access the HTML rendered output with `component.nativeElement`, for example :
   ```commandline
   const html = fixture.nativeElement;
   expect(html.querySelector('p').textContent).toContain('AAA');
   ```

When the component is modified (for example a member variable's value is changed), Angular usually updates the HTML output
automatically, but this is not automatic in tests.  
To trigger the change detection, we must call the `fixture.detectChanges()` method. 

If we need to test an async calculation (like a call to an external API returning a Promise) we can :
 - create a spy of the service and mock the async function to test (to not actually call the API)
   ```commandline
   let service = fixture.debugElement.injector.get(UserService);
   let spy = spyOn(service, 'methodName').and.returnValue(Promise.resolve('XXX'));
   ```
 - wrap the lambda function of the test into the `async()` function.  
   After the promise call, detect the changes and inform Angular to wait for the completion of the async call :
   ```commandline
   fixture.detectChanges();
   fixture.whenStable().then(() => { /* assertions */ });
   ```


## Useful external libraries and tools

### Prettier

`Prettier` is a code formatting library supporting multiple languages used by Angular (JS, TS, HTML, CSS, JSON...).  
It can be installed and saved to `package.json` with `npm install prettier --save-dev`

It is an opinionated code formatter, that intentionally offers very little flexibility on how to style the code.   
Instead, it enforces a formatting style and rewrites all the code accordingly.

Its intent is not to give granular flexibility on the coding style, but to help developers focus on writing code without
arguing on the best coding style.
Developers can simply run the Prettier formatting on their code, and it guarantees a consistent coding style across the entire project.

To run the formatting on all the code of a project, run :
```commandline
npx prettier --write .
```

Prettier supports a few configuration options (mostly for historical reasons, and the team will not add more).  
Those options can be set in a `prettierrc.json` configuration file.
