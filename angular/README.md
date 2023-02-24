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
```commandline
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
  To use the same instance across all components, it is common to declare it in the top-level module.   
  If the service is provided at module level, it can also be injected in services.  


- Add `{ providedIn: 'root' }` parameter to the `@Injectable()` decorator of the service (Angular 6+)  
  This automatically provides the service at module level (no need to add it in the module manually)   
  This is the preferred method to ensure a single instance of the service is used across the app.

Services can be used for inter-components communication using `Subject` or `BehaviorSubject` emitters.  
This is much simpler than passing around data from component to component with `@Input()` and `@Output()` chains.


# Angular Modules

Every Angular app has at least 1 module, called `AppModule` by default.  
We can create other Angular modules to group components related to a given feature.  
This makes the code more readable, maintainable and allows performance improvements (lazy loading).  
Every module contains some components / directives / pipes ...  
A component / directive / pipe is part of one and only one module.  
Services are usually included app-wide with the `{ providedIn: 'root' }` parameter in the `@Injectable()` decorator, so they do not appear in any module definition.

A frequent module is `app-routing.module.ts` in charge of the routing.  
It can optionally be added at project creation with `ng new` if selecting the "routing" option.

There are some built-in Angular modules, for example the `FormsModule` containing the `ngModel` directive.  
All modules used in an app (custom and builtin) must be listed in the `imports` of AppModule (or of the feature module using them).  
Import a module means importing everything this module exports.  
Everything else the module declares but does not export is not accessible.  
That is why the `AppRoutingModule` updates the `RouterModule` (with the `forRoot()` or `forChild()` method), and then exports it.  

To create a feature module, we create a TS class with the `@NgModule()` decorator and properties :
 
- `declarations` : All components that belong to this module (each component is declared in a single module)


- `imports` : Modules containing some components used in the module (AppRoutingModule, FormsModule,...)  
              It must always contain CommonModule (or a module exporting it, like a custom SharedModule).


- `exports` :      all components that we want to make available to other modules importing this module.  
                   The components only used inside this module do not need to be exported.

Routes related to a feature module can be moved into a dedicated `xxx-routing.module.ts` module.  
It must import the RouterModule, call its `forChild()` method, and export it :
```commandline
    RouterModule.forChild(routes)
```

We can also create one (or several) shared module. It is very similar to a feature module, but it exports all its components so other modules that import it can include these components in their templates.

We see sometimes a `CoreModule` in some Angular projects.  
It is meant to include all the services that will be available across the app.  
This is no longer recommended now that services can be provided across the app in their `Injectable()` decorator.  

### Module Lazy Loading

We can use lazy loading to associate some roots with a module, and load the components in the module only when one of its routes were called.  

- add in the `app-routing.module.ts` file a route without a `component` property, but with a `loadChildren` property with a lambda returning the name of the module to load lazily.
```commandline
path: 'recipes', loadChildren: () => import('./recipes/recipes.module').then(m => m.RecipesModule)
```
 

- in the routing of the lazily loaded module, the `root` route should now be `''`, since the root route is now included in app-routing and loads the child module.


- remove the lazily loaded module from the TS and Angular imports in AppModule.  

 
With this in place, we can see in the Network inspector of the browser debugger that the `main.js` file is smaller.
When navigating to a route in the lazily loaded module, the browser loads another JS bundle for this module.  

By default, lazily loaded modules are loaded only the first time one of their routes is called.  
To improve the performance, we can set the loading strategy to preload all modules in `app-routing.module.ts` :
```commandline
  imports: [ RouterModule.forRoot(routes, {preloadingStrategy: PreloadAllModules}) ],
```


## Angular Directives

### Built-in Directives

Directives are properties that can be assigned to an HTML tag to modify its behavior.  
Angular ships with some built-in attribute and structural directives.

Structural directives are directives that modify the DOM, they are prefixed with the `*` symbol.  
They are just a trick to write more readable code, but they are not real directives.  
They get transformed by Angular into valid HTML code using the corresponding attribute directive (without the `*` prefix).

- Conditional inclusion :  ***ngIf**  
  Take a boolean value, display the tag if the TS results to true.
  ```commandline
    <p *ngIf="shouldDisplay"> XXX </p>
  ```
  The syntax is a bit strange when it specifies an else block :
  ```commandline
    <p *ngIf="shouldDislay; else #other"> XXX </p>
    <ng-template #other> <p> YYY </p> </ng-template>
  ```
  Behind the scene, Angular transforms the template with the structural directive into :
  ```commandline
  <ng-template [ngIf]="shouldDisplay">
    <p> XXX </p>
  </ng-template>
  ```


- Selection of a tag among several : **ngSwitch** / ***ngSwitchCase** / ***ngSwitchDefault**  
  Only the directives for the options of the switch have a `*` prefix.
```commandline
    <div [ngSwitch]="value">
      <p *ngSwitchCase="1"> I am 1 ! </p>
      <p *ngSwitchCase="2"> I am 2 ! </p>
      <p *ngSwitchCase="3"> I am 3 ! </p>
      <p *ngSwitchDefault> I am not 1, 2 or 3 ! </p>
    </div>
```


- Repeat a block multiple times :  ***ngFor**  
  Repeat a block for all elements of an input array.  
  ```commandline
  <p *ngFor="let server of serverNames"> {{server}} </p>
  ```
  We can get the current loop index with the `index` variable that Angular provides :
  ```commandline
  <p *ngFor="let server of serverNames; let i = index"> Loop {{i}} : {{server}} </p>
  ```


- Dynamic style: **ngStyle**  
  Defines some CSS styles for the tag, it takes a map of property/value pairs.  
  It has no `*` prefix, as it does not modify the DOM structure.
  ```commandline
  <p [ngStyle]="{backgroundColor: getColor()}"> XXX </p>
  ```


- Dynamic classes: **ngClass**  
  Defines some CSS classes for the tag, it takes a map of string/boolean, to decide if each class is attached to the tag.  
  It has no `*` prefix, as it does not modify the DOM structure.
  ```commandline
  <p [ngClass]="{online: isOnline()}"> XXX </p>
  ```


### Custom Attribute Directives

We can create custom directives in Angular, as a TS class with the `@Directive()` decorator.  
The directive needs to be added in the `declarations` of the module for Angular to know it.  
The reference of the element that uses this directive can be injected from the decorator :

```commandline
@Directive({
  selector: '[appBasicHighlight]'
})
export class BasicHighlightDirective implements OnInit {

  // inject the ElementRef and shortcut to make it a property
  constructor(private elementRef: ElementRef) {}

  ngOnInit() {
    this.elementRef.nativeElement.style.backgroundColor = 'blue';
  }
}
```

This directive can then be used in our HTML like this :

```commandline
   <p appBasicHighlight> I am blue ! </p>
```

It is not recommended to directly amend the style of an HTML element from the TS code though.  
A better approach is to use a renderer, also injectable by Angular in the constructor :

```commandline
   constructor(
     private elementRef: ElementRef,
     private renderer: Renderer2
   ) {}
   
   ngOnInit() {
     this.renderer.setStyle(this.elementRef.nativeElement, 'background-color', 'blue');
   }
```

### Dynamic Custom Attribute Directives

The directive can react to an event happening in the host component by defining a method with `@HostListener()` decorator.  
For ex for the directive to set a blue background on hover, we can define in the directive TS file :

```commandline
  @HostListener('mouseenter') onMouseOnter(eventData: Event) {
     this.renderer.setStyle(this.elementRef.nativeElement, 'background-color', 'blue');
  }

  @HostListener('mouseleave') onMouseLeave(eventData: Event) {
     this.renderer.setStyle(this.elementRef.nativeElement, 'background-color', 'transparent');
  }
```

If we just need to bind to a property of the host component, a simpler way is to use `@HostBinding()` instead of using the renderer.  
It binds a property of the host element to a field of our directive :

```commandline
  @HostBinding('style.backgroundColor') bgColor: string = 'transparent';

  @HostListener('mouseenter') onMouseOnter(eventData: Event) {
     bgColor = 'blue';
  }

  @HostListener('mouseleave') onMouseLeave(eventData: Event) {
     bgColor = 'transparent';
  }
```

A directive can receive some parameters with the `@Input()` decorator, just like a component:

```commandline
  @Input() highlightColor : string = 'blue';
```

To pass the parameter to the directive, we bind it just like we do for a component.  
Angular figures out if the specified property is for the component or for one of its directives :

```commandline
<p appBasicHighlight [highlightColor]="'red'"> I am red ! </p>
```

We can give the `@Input()` property the same name as the directive, so we can bind using the directive itself (like it is done for the built-in `ngClass` and `ngStyle` for example) :

```commandline
  @Input('appBasicHighlight') highlightColor : string = 'blue';
```

So we can bind it in the HTML template :

```commandline
<p [appBasicHighlight]="'red'"> I am red ! </p>
```

This obviously can be used only with a single `@Input()` property, others need the normal binding if there are more than one.


### Custom structural directives

Structural directives (prefixed with `*`) are no native directive in Angular, just syntactic sugar.  
Tags with `*ngIf` get wrapped by Angular into a `<ng-template>` element with a `[ngIf]` property (without the `*`).  
The `<ng-template>` itself is not added to the DOM, but its content is added if the condition evaluates to true.

To implement custom structural directives, it is similar to attribute directives, but we now need to tell Angular what to display, via two elements we can inject :
 - **TemplateRef**      : a reference to the template containing the content to display or not
 - **ViewContainerRef** : a reference to the container where the template is included

We can use a setter for the `@Input()` to execute a method when it is set.  
This method will decide whether or not to include the element in the view.  
For example, a directive "unless" that displays an element only if a condition is false :

```commandline
@Directive({
  selector: '[appUnless]'
})
export class UnlessDirective {

  // here we use a setter instead of a prop, so the method is called everytime "unless" is defined
  @Input() set appUnless(condition: boolean) {
    if (!condition) {
        this.vcRef.createEmbeddedView(this.templateRef);
    } else {
      // do not display the template, clear the view container
        this.vcRef.clear();
    }
  }

  // inject the template ref and the view container ref as properties
  constructor(
    private templateRef: TemplateRef,
    private vcRef : ViewContainerRef
  ) {}
}
```

It can then be used like :

```commandline
  <div *appUnless="shouldBeHidden"> XXX </div>
```


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



## Angular Deployment

The Angular project is build for production with :  `ng build`  
This uses by default the production configuration since Angular 12.  
This will generate under the _dist/_ folder a few files that we can deploy to run our app.  
These files are a shrinked version of the app code.

After the artifacts (generated files) are built, we get only HTML / CSS / JS code.  
This can be deployed to a static website host that delivers only HTML / CSS / JS files.  
Popular options are **AWS S3** (need AWS account) and **Firebase Hosting** (independent from the Firebase Realtime Database).  

If the app calls a backend, we need to ensure that they can communicate (REST API).

### Deploy with Firebase Hosting

Firebase hosting offers hosting service for static (HTML/JS/CSS) and dynamic (Express) websites.  
We can link it to use a custom domain name if needed.

Firebase Hosting website : https://firebase.google.com/docs/hosting

```commandline
   $>  npm install -g firebase-tools      # install Firebase CLI
   $>  firebase login                     # login to the Google account (prompt a browser login)
   $>  cd <project_path>                  # move to the project folder
   $>  firebase init                      # initialize the project in Firebase
       -> select "Hosting" with Space, then Enter
       -> select the Firebase project created earlier (or create a new one if didnt use Firebase earlier)
       -> for the folder, do not use "public", replace by the folder of our code (dist/recipe-app for ex)
       -> Single-page app : "y"
       -> automatic builds and deploys with GitHub -> N
       -> overwrite index.html: "N"
   $>  firebase deploy                    # deploy the dist/ folder to Firebase
```

This outputs an URL where the Angular app is available on Firebase servers.  
The deployed files can now be seen in the Hosting tab of the Firebase console of this project.

### Ahead of Time compilation

When running `ng serve -o`, we are running a web server and shipping the Angular compiler in the app.  
Everytime we query some component, the compiler will be called in the browser to convert Angular templates into JS code.  
This is called "Just In Time" compilation, which is great for debugging.  
In production, we want to pre-compile to JS and not ship the Angular compiler, this is "Ahead of Time" compilation.  
It is stricter than the "Just In Time" compiler used in debug, so new compilation errors can occur.  
If some TS code is not understood in the template, we can usually move it to a method in the TS class definition.

### Environment variables

Angular offers in `./src/environments/` a production and development file for environment variables.  
The `env` object can store some key/value pairs.  
When Angular builds the code, it uses the production file when using `ng build` and the development file when using `ng serve`.
This replacement is performed by the `fileReplacements` property in the `angular.json` configuration file.  
It allows to have different API keys or URLs for production and development for example.  
To use it in components or services, just import `environment` from `src/environments/environment`

Since Angular 15, `ng new` no longer generates the environment file by default.  
The `fileReplacements` property is still available in `angular.json` though.  
We can configure it manually, or call `ng generate environments` to get Angular set it up as it used to be.


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
