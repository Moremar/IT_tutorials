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
ng help                     List all available commands
ng v                        Version of Angular / Node / OS
ng <cmd> --help             Help for a specific ng command
ng new projectName          Create an empty Angular project
ng serve                    Build the app and start a web server
                            -o to open the app in a browser
                            --port to specify a port (default 4200)
ng g c path/componentName   Generate a new component (HTML + TS + CSS + Test)
                            Can be ran from the project root (no need to specify src/app/)
                            --flat to not create a dedicated folder for that component
ng g g path/guardName       Generate a new guard (TS)
ng g m path/moduleName      Generate a new module (TS)
ng g d path/directiveName   Generate a new directive (TS)
ng lint                     Run the linter
ng test                     Run the tests
ng e2e                      Run the end-to-end tests
ng build                    Build app for deployment into the /dist folder
ng update                   Update the project to latest angular version
ng add <external_lib>       Use NPM to install a lib and run a script to setup the Angular project to use it
ng add @angular/material    Example of "ng add", to install Angular Material components
ng add @angular/fire        Example of "ng add" to install the Firebase CLI
ng deploy <package>         Deploy the code to a destination target
                            This needs to specify what to deploy to, and the deployment steps will be in the package
                            Some valid targets are Firebase Hosting, Github pages, AWS, Azure ...
ng deploy @angular/fire     Deploy the Angular project to Firebase
                           
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


## Angular Modules

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


## Angular Pipes

Pipes can be used to transform some data in the output HTML template.  
They are used with string interpolation to transform the value resolved in TS :

```commandline
{{ 'Hello' | uppercase }}     //  HELLO
```

Angular ships with some built-in pipes :

```commandline
uppercase
date               // format a date like 'Aug 12, 2017' by default
json
slice              // substring
async              // wait for Promise resolution and update when it resolves
```

Some pipes can take parameters, provided after a `:` symbol :

```commandline
{{ myDate | date: 'fullDate' }}     // format a date like 'Monday, August 12, 2017'
```

Pipes can be chained :

```commandline
{{ myDate | date: 'fullDate' | uppercase }}
```

A custom pipe can be create in a `xxx.pipe.ts` file by implementing the `PipeTransform` interface.  
It should have the `@Pipe()` decorator with the `name` property.  
The pipe should then be added to the `declarations` array of a module, just like any component.

```commandline
  @Pipe({ name: 'firstLetters' })
  export class FirstLettersPipe implements PipeTransform {
    transform(value: any, size: number) {
      return value.substr(0, size);
    }
  }
```

Pipes can return any type of data, and can also be used in `*ngFor` loops in the HTML code to filter the array we loop on.  
If `validUsers` is a pipe taking users in parameter and returning an array of valid ones, we can use :

```commandline
<div *ngFor="let user of users | validUsers"> ... </div>
```

By default, the pipe is not recalculated when the array changes (it would be high performance).  
This means that if new valid users are created, they would not be listed in the above example.  
We can force Angular to recalculate the pipe on every change in the page by adding `pure: false` in the `@Pipe()` decorator.  
It is not the default because that may slow down the app.

The `async` pipe can also be used with Promise or Observable objects.  
By default, if we output a promise object, it will only show `[Object object]`  
In the case the promise resolves to a string after X seconds, we may want to only display the value after resolution.  
In that case we can use `{{ myPromise | async }}`, which will not display anything as long as the promise is pending, and will display the resolved string when the promise is resolved.


## Angular Forms

In usual web applications, forms send a request to the server, that will reply with an HTML page.  
Angular applications are single-page applications, so we need to handle the form ourselves.  
If we want to reach out to a server, this will be done via the Angular HTTP service.  
Angular offers great tools to check the form validity and handle the inputs.  
It requires to import `FormsModule` in the `imports` property of the `app.module.ts` file.

There are two approaches to handle forms in Angular :

 - **template-based**  
The simplest approach, we define the form structure in the HTML template.  
Angular automatically creates a TS object representing the form and lets us manipulate it.  
It is sufficient for most scenarios.


 - **reactive**  
We define manually TS form object and all its controls, create the HTML form in the template and specify the bindings.  
It is more complex than the template-based approach, but allows more fine-tuning (dynamic controls, custom validators...)

### Template-based approach

In the HTML form, we need to let Angular know which controls must be included in the TS representation.  
For that, we add the `ngModel` property (with no param) and and the `name` property to all our controls :

```commandline
<input type="text" id="username" class="form-control" ngModel name="username" />
```

By default, when a button with `type="submit"` inside a form is clicked, a submit event is triggered.  
Angular uses this behavior so instead of adding a `(click)` listener to our button, we add a `(ngSubmit)` listener to the `<form>` tag.

We can access the TS form object by setting a local reference to the form and assigning it to `"ngForm"`, then give it to the TS method called on submit :

```commandline
<form (ngSubmit)="onSubmit(myForm)" #myForm="ngForm"> [...] </form>
```


From the TS component definition, we can access this NgForm object parameter.  
Its `value` attribute contains the value of each control in the form :

```commandline
  onSubmit(myForm: NgForm) {
    console.log(myForm.value);
  }
```

An alternative design is to not pass any parameter to `onSubmit()`, but in the component get the form with `@ChildView()`.  
It is useful if we want to access the content of the form from outside the form submit function :

```commandline
  @ChildView('myForm') myForm: NgForm;
```


#### Form Validation

We can add some built-in directives in our controls to define some validation :

```commandline
   required
   email
   maxlength="25"
   pattern="[a-zA-Z ]*"       // text only
   pattern="^[1-9][0-9]*$"    // positive number
```

The result of the validation will be in the `valid` property of the NgForm TS object.  
Angular also adds some CSS classes to the controls depending on their status :

```commandline
  ng-valid
  ng-invalid
  ng-dirty         // modified
  ng-touched       // clicked but not necessarily modified
  ng-untouched     // not even clicked
```

This lets us style invalid inputs, for example :

```commandline
  input.ng-invalid.ng-touched { border: solid 1px red; }
```

We can also add an error message displayed only if the input is invalid.  
This requires to give a local reference to the input of type ngModel :

```commandline
  <input type="text" class="form-control" name="email" ngModel email #myEmail="ngModel" />
  <p class="help-block" *ngIf="myEmail.touched && !myEmail.valid"> Enter valid email </p>
```

The submit button can be disabled if the form is not valid :

```commandline
  <input type="submit" class="btn btn-primary" [disabled]="!myForm.valid" />
```

#### Default value

We can add a default value to a control (input or select) with one-way binding on the `[ngModel]` directive :  

```commandline
<select class="form-control" id="question" name="question" [ngModel]="'age'">
  <option value="age">How old are you ?</option>
  <option value="name">What is your name ?</option>
</select>
```

If we need to access the value from TS before the submit button is clicked, we can use 2-way bindings on the `[(ngModel)]` directive.  
This can be used for example to verify if a username is not already taken.


#### Form Groups

We can group several controls together inside a form group in Angular with the `ngModelGroup` directive.  
Angular will take it into account when creating the NgForm object, each group will be a level in the `value` property of the form, as well as in the `controls` property, with its own valid/touched/dirty... properties.  

We can also set a reference to the form group of type `ngModelGroup` to access it from somewhere in the HTML template.

```commandline
<form (ngSubmit)="onSubmit()" #myForm="ngForm">
  <div id="userInfo" ngModelGroup="userData" #userData="ngModelGroup">
    <div class="form-group">
      <label for="username"> User Name </label>
      <input class="form-control" type="text" id="username" name="username" ngModel required />
    </div>
    <div class="form-group">
      <label for="password"> Password </label>
      <input class="form-control" type="text" id="password" name="password" ngModel required />
    </div>
  </div>
  <p *ngIf="userData.touched && userData.invalid">The User data are not valid ! </p>
</form>
```

In the above example, `ngModelGroup="userData"` tells Angular to include that form group in its ngForm object representation.  
`#userData="ngModelGroup"` defines a local reference on that form group of type `ngModelGroup` (instead of HTML element if nothing specified) that can be accessed in the template, for example in a `*ngIf` condition.


#### Select dropdown

```commandline
<div class=form-group">
  <label for="status">Project Status</label>
  <select id="status" ngModel name="projectStatus">
    <option value="stable">Stable</option>
    <option value="critical">Critical</option>
    <option value="finished">Finished</option>
  </select>
</div>
```

#### Radio-button

For radio buttons, each option must be an input wrapped in a `<label>` tag.  
All options are in a `<div>` tag with class `"radio"` :

```commandline
<div id="myRadioContainer">
  <div class="radio">
   <label> <input type="radio" name="gender" value="H" ngModel /> Male </label>
   <label> <input type="radio" name="gender" value="F" ngModel /> Female </label>
  </div>
</div>
```

#### Update control value from TS

We can update control values from the TS code with 2-way data binding `[(ngModel)]` directive.  
Angular also offers form-specific functions to update either all the form values or specific ones.  
For this, we need to have a local reference `#myForm` on the form and retrieve it with an `@ChildView()` property.  
Then we can call :

```commandline
  this.myForm.setValue({ userData: { username: 'Bob', password: '1234'}, email: 'aaa@aaa.com' });
  this.myForm.form.patchValue({ userData: { username: 'Bob' } });
```

We can also reset the form to the initial values and state (all CSS classes) with :

```commandline
  this.myForm.reset();
```

### Reactive approach

With the reactive approach, we still define our form in the HTML, but we no longer use the NgForm representation that Angular creates automatically.  
We need to import the `ReactiveFormsModule` in the `app.module.ts` (instead of `FormsModule` for template-based forms).  
Then we define a property `myForm` of type `FormGroup` (the NgForm class is actually a wrapper above it).  
We can populate it in the `ngOnInit()`, by defining the controls of the form.  
In this FormGroup, there is no difference between input / select / radio controls.  
We can have a tree structure by adding other FormGroup elements inside the root FormGroup.

```commandline
  ngOnInit() {
    this.myForm = new FormGroup({
      'userData': new FormGroup({
        'username': new FormControl('default name'),
        'password': new FormControl(null),
      }),
      'gender': new FormControl('H'),
    });
  }
```

In the HTML, we need to let Angular know that we want to link our `<form>` tag with our custom TS FormGroup :

```commandline
<form [formGroup]="myForm">
```

Then all controls need to have the `"formControlName"` directive to link to the control name in the TS form object :

```commandline
<input type="text" id="username" class="form-control" formControlName="username">
```

Similarly, the form groups inside the root must be represented by a div with `"formGroupName"` directive :

```commandline
<div formGroupName="userData">
```

On submit, it is very similar to the template-based version.  
The form has a `(ngSubmit)` listener calling an onSubmit() function.  
Now the `onSubmit()` function can access the forms values from the myForm object it created.

Validators on controls should not be in the HTML anymore, but in the TS form definition.  
The `FormControl()` constructor takes a default value and the validator(s) to apply.

```commandline
  new FormControl('default val', [Validators.required, Validator.email])
```

To display a message when a component is invalid, it is the same logic as for template-based, but we use the `get` method of the FormGroup to access a given controller :

```commandline
  <input type="text" id="username" class="form-control" formControlName="username">
  <span *ngIf="myForm.get('userData.username').touched && !myForm.get('userData.username').valid">Enter a valid name !</span>
```

#### Dynamic FormArray Controls

We can also use some arrays of controllers, by declaring a FormArray inside the FormGroup.  
Then it needs to be linked in the HTML with `"formArrayName"` property :

```commandline
<div formArrayName="guests">
  <h1> Guests </h1>
  <button type="button" class="btn btn-primary" (click)="onAddGuest()"> Add Guest </button>
  <div class="form-group" *ngFor="let guest of myForm.get('guests').controls; let i = index">
    <input type="text" class="form-control" [formControlName]="i" />
  </div>
</div>
```

We can add dynamically an empty element in the `guests` form array from the TS code.  
That requires a cast to `<FormArray>` to let TS know that we are using an array and can push to it :

```commandline
  newControl = new FormControl(null, Validators.required);
  (<FormArray>this.myForm.get('guests')).push(newControl);
```

#### Custom validators

The reactive approach lets us easily define custom validators.  
We just need to implement a validator function and pass it to the `FormControl()` constructor of a control.  
This validator function must return `null` if no issue, or an object of the form `{ 'myValidationName' : true }` on error.

```commandline
  blacklistedGuests = ['Bob', 'Alice'];

  notBlacklisted(control: FormControl) : { [s: string]: boolean } {
    if (this.blacklistedGuests.indexOf(control.value) !== -1) {
      return { 'blacklistedName': true };
    }
    return null;
  }
```

_NOTE_ :  We need to bind `this` so TS knows what to use as the `this` when it calls the validator from Angular !

```commandline
  newControl = new FormControl(null, [Validators.required, this.notBlacklisted.bind(this)]);
```

#### Using error codes

The error code is saved in the TS form object inside the component that causes the error.  
This can be used to display a custom validation message depending on the error :

```commandline
    <input type="text" class="form-control" [formControlName]="i" />
    <span *ngIf="myForm.get('userData.username').touched && !myForm.get('userData.username').valid">
      <span *ngIf="myForm.get('userData.username').errors['required']"> Should not be empty ! </span>
      <span *ngIf="myForm.get('userData.username').errors['blacklistedName']">  Blacklisted Name ! </span>
    </span>
```

#### Asynchronous Validation

An asynchronous validator can be created when the validation takes time, for example to reach out to a backend via HTTP.  
It is similar to a synchronous validator, but it returns a Promise or an Observable :

```commandline
  nameForbidden(control: FormControl): Promise<any> | Observable<any> {
    const promise = new Promise<any>( (resolve, reject) => {
      setTimeout(() => {     // just to simulate a time-consuming function
        if (control.value == John'') {
          resolve({ 'forbiddenName': true });
        } else {
          resolve(null);
        }
      }, 1500);
    });
    return promise;
  }
```

In the declaration of the control, it should be added in the 3rd argument (as for synchronous validators, bind `this` if used) :

```commandline
  newControl = new FormControl(null, [Validators.required], [this.nameForbidden]);
```

We can subscribe to `myform.valueChanges` or `myForm.statusChanges` ovservables to react to those changes.  
This can also be done on individual form controls.


## Angular Router

### Routes definition

An Angular app is a single-page component, but Angular offers a routing mechanism to make it look like the user navigates across different pages, by changing the URL and displaying some specific components depending on the selected route.

We can add routes and their associated components in `app.module.ts` :

```commandline
  routes: Routes = [
    { path: '', component: HomeComponent },           // localhost:4200
    { path: 'users', component: UsersComponent },     // localhost:4200/users
    { path: 'cards', component: CardsComponent }      // localhost:4200/cards
  ];
```

We need to import the router module and give it the routes defined above :

```commandline
  imports: [
     ...
     RouterModule.forRoot(routes)
  ]
```

Then in the HTML component where we want routing (most likely in the `app.component.html` top-level component), we add an Angular directive to display the component of the selected route.
This will indicate to Angular where in the DOM to load the component configured for that route.

```commandline
  <router-outlet><router-outlet>
```

### Router links

Most apps have some links to navigate from one page to another, for example buttons in the header bar.  
Using `href="/users"` is not correct, as it reloads the entire app and thus lsoes the app state.  
Instead we use the `routerLink` directive, that can take either a string or an array of segments :

```commandline
  <a routerLink="/users"> XXX </a>
  <a [routerLink]="['/users', '123']"> XXX </a>    // route to localhost:42000/users/123
```

A route starts with `/` for an absolute route and without it for a relative route.

To style our links when they are active, Angular offers the `routerLinkActive` directive that can receive a class to attach to the element when it is active.
This directive can be attached to a `<a>` or a `<li>` tag.

By default, the class given with the `routerLinkActive` directive is attached if the path is included in the current path.  
This is an issue for the root path `/` (usually used for the app home) that is included in all routes.  
We can pass options to the `routerLinkActive` directive to force an exact match :

```commandline
  <ul class="nav nav-tab">
    <li routerLinkActive="active" [routerLinkActiveOptions]="{exact: true}"> <a routerLink="/users"> Home </li>
    <li routerLinkActive="active"> <a routerLink="/users"> Users </li>
    <li routerLinkActive="active"> <a routerLink="/cards"> Cards </li>
  </ul>
```

To navigate to a route programmatically, we can inject the `Router` element in the constructor and call :

```commandline
  this.router.navigate(['/users', '123']);
```

This `navigate()` method has no knowledge of the component it is called from, so it navigates to an absolute route.  
To navigate to a relative route, we must specify to Angular the route to use as a reference.  
Inject the current route of type `ActivatedRoute` in the constructor, and pass it to the `navigate()` method :

```commandline
  this.router.navigate(['users', '123'], {relativeTo: this.activatedRoute});
```

### URL parameters / query parameters / fragments

We can define dynamic segments in a route in app.module.ts by prefixing the segment with the `:` symbol :

```commandline
    { path: 'users/:id', component: UserComponent },  // localhost:4200/users/123
```

Query params (like `?readOnly=Y` for example) can also be added to the Angular routes.  
From the HTML code, we can use the `queryParams` property of the `routerLink` directive :

```commandline
  <a routerLink="/users/123" [queryParams]="{readOnly: 'Y'}"> XXX </a>
```

Fragments (like `#conclusion` for example) can also be added with the `fragment` property (just a string so does not need [..]):

```commandline
  <a routerLink="/users/123" fragment="conclusion"> XXX </a>
```

URL parameters, query parameters and fragments can be retrieved from TS in the `ngOnInit()` method of the component.  
We must inject the active route of type `ActivatedRoute` and access them from its snapshot :

```commandline
  this.activatedRoute.snapshot.params['id'];
  this.activatedRoute.snapshot.queryParams['readOnly'];
  this.activatedRoute.snapshot.fragment;
```

They can be added programmatically through the options param of the `navigate()` method :

```commandline
  this.router.navigate(['/users', '123'], { queryParams: { readOnly: 'Y' }, fragment: 'conclusion'});
```

To react when the URL parameters, query parameters or fragment change, we can subscribe to its observable.  
The `ActivatedRoute` object has Observable properties with the same name as inside the "snapshot" property :

```commandline
  this.activatedRoute.params.subscribe(
    (params: Params) => { this.userId = params['id']; }
  );
```

Theoretically we should unsubscribe in the `ngOnDestroy()` hook, but we do not have to do it because Angular already cleans the subscription for us when the component is destroyed (only for Angular observables).

Note that when we navigate to a different route of our app, we lose the current query parameters by default.  
To preserve the current query parameters or merge with some new ones, we can set the `queryParamsHandling` option :

```commandline
  this.router.navigate('edit', {relativeTo: this.activatedRoute, queryParamsHandling: 'preserve'});
```

### Nested Routes

We can define sub-routes in a route if we want a hierarchy of pages in an Angular app.  
If we write this in app.module.ts :

```commandline
    { path: 'users', component: UsersComponent },     // localhost:4200/users
    { path: 'users/:id', component: UserComponent },  // localhost:4200/users/123
```

Then `users/:id` route is not a child of the `users` route, it is an independant route.  
When resolcing the component to load for URL `users/123`, the Angular router will load `UsersComponent`, not `UserComponent`.  
If we use an exact match, then `UserComponent` is loadded but not `UsersComponent`.  
In case of a child route, we want to load `UsersComponent`, and somewhere inside its HTML template we want to load `UserComponent`.  

When we have multiple levels of `<router-outlet>` tags to load components, we can use children routes :

```commandline
    { path: 'users', component: UsersComponent, children: [
        { path: ':id', component: UserComponent }
    ] },

```
In this case we need to have another `<router-outlet>` inside the HTML template of `UsersComponent` to specify where to include the loaded child component.

### Wildcards and Redirection

We can redirect a route to another one with :

```commandline
    { path: '/home', redirectTo: '/' }
```

A default route can be specified in case no previous route matched.  
It needs to be the last route defined, since routes are evaluated in order :

```commandline
    { path: '**', component: NotFoundComponent }
```

### External Routing module

It is a good practice to use a separate module for the routing of our app.  
We can create an `app-routing.module.ts` file (created by default by CLI is we specify routing) :
 - create a `AppRoutingModule` with the `NgModule()` decorator
 - add the routes definition (of type `Routes`) before the `@NgModule` decorator
 - in the `imports` of AppRoutingModule, add `RouterModule.forRoot(routes)`
 - in the `exports` of AppRoutingModule export the `RouterModule`
 - in the import of AppModule add this `AppRoutingModule` to make it aware of the routes


### Passing data to the loaded component

When defining the route, we can provide the `data` property (map of key/value pairs).  
Just like queryParams, it can then be accessed in the component via the injected `ActivatedRoute` instance :

```commandline
  this.activatedRoute.snapshot.data['myData']
```


## Angular Guards

### Activation guard

We can create a guard to prevent a route to be loaded under some conditions.  
A guard is a service that implements the `CanActivate` interface, that returns either a `boolean`, a `Promise<boolean>` (that will return later) or an `Observable<boolean>` (that must be subscribed to).  
It can also return a `UrlTree` in case we want to redirect the user to another URL (to auth for example).  
Since it is a service, the guard needs should have `'providedIn': 'root'` in its `@Injectable()` decorator.

For example, if we have an authentication service with an `isLoggedIn()` method returning a `Promise<boolean>`, we can define an authentication guard like :

```commandline
export class AuthenticationGuard implements CanActivate {

  constructor(
    private authService: AuthenticationService,
    private router: Router
  ) {}

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot) :
      boolean | UrlTree | Observable<boolean | UrlTree> | Promise<boolean | UrlTree> {
    this.authService.isLoggedIn().then(
      (loggedIn : boolean) => {
        if (loggedIn) {
          return true;
        } else {
          return this.router.createUrlTree(['/login']);
        }
      }
    );
  }
}
```

The guard needs to be added to the `canActivate` property of the route we want to protect.  
It will automatically apply on all its children.  
We can have several guards for each route.

```commandline
  { path: '/users', component: UsersComponent, canActivate: [AuthenticationGuard] }
```

To allow access to the parent route but add a guard only to the children routes, we can use `canActivateChild` instead of `canActivate`.

### Deactivation guard

It can be useful to create a guard to check if we can safely leave a route.  
A typical example is to check for unsaved changes and display a confirmation popup.  
This can be used by implementing the `CanDeactivate` interface.  
The pattern is to create a `SafeToLeave` interface that has a single method `safeToLeave()` implemented by the component.  
Then the guard calls this `safeToLeave()` method from the component when it tries to leave the route :

```commandline
  export interface SafeToLeave {
    safeToLeave : () => boolean | Promise<boolean> | Observable<boolean>;
  }

  export class CanDeactivateGuard implements CanDeactivate<SafeToLeave> {
    canDeactivate( component : SafeToLeave,
                   currentRoute: ActivatedRouteSnapshot,
                   currentState: RouterStateSnapshot,
                   nextState?: RouterStateSnapshot): boolean | Promise<boolean> | Observable<boolean> {
     return component.safeToLeave();
   }
  }
```

### Resolver guard

We can use a resolver guard to fetch data from a backend before we actually display the routed component.  
We must create a resolve guard service implementing the `Resolve` interface.

```commandline
  export class ServerResolveGuard implements Resolve<Server> {
    constructor(private serversService: ServersService) {}

    resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot) : Server | Promise<Server> | Observable<Server> {
      return serversService.getServer(+route.params['id']);
    }
  }
```

In the routing module we add to the route the `resolver` property taking a map of (resolver name, resolver guard) :

```commandline
 { path: '/servers/:id', component: ServerComponent, resolve: {server: ServerResolveGuard} }
```

From the ServerComponent, the resolved server can be accessed in the `data` property of the active route :

```commandline
  this.activatedRoute.snapshot.data['server']      // if we just need it at initialization
  this.activatedRoute.data.subscribe(
    (data: Data) => { this.server = data['server']; }
  );
```



## Communication with a Backend

To communicate with a backend, Angular can send some HTTP requests via its HTTP module.  
HTTP requests are made of :
 - a verb  : GET / POST / PUT / DELETE / PATCH ...
 - a URL   : /recipes/12/
 - headers : content-type, ...
 - a body  : the data to send (for POST / PUT / PATCH)


Here we use a Firebase project so we do not need to write our own backend.
Firebase gives us some endpoints to create/alter/delete objects.
See at the end for more info about Firebase.


### Firebase Backend

In a real Angular app, the backend can be in any server-side language (C++, Java, Node, Python...).  
To simulate a simple backend, we can use Firebase, a Google backend-as-a-service solution.  
It offers most backend functionalities (authentication, database, storage, REST API).  
To create a simple backend for an Angular app, we can use a REST API to define HTTP endpoints and the authentication solution generating auth tokens.  
A Firebase project is a container for several apps sharing a backend (iOS / Android / web).  
It is actually creating a Google Cloud Platform (GCP) project behind the scene.

#### Firebase Realtime Database

We can use Firebase Realtime database, a database that stores and gets objects directly via HTTP calls.  
When sending a POST, it is interpreted by Firebase to add an element in a folder of this database.

- open [Firebase home page](https://console.firebase.google.com) (require a Google account)
- Click "Create a Project" and give it a name.
- Once the project is created, it appears in the dashboard.
- Navigate to Build > Realtime Database > Create Database  
  Click "Start in test mode" to allow anyone to do anything in the DB (later we will use authentication)
- 
- We then see a URL like    

The `Data` tab of the database section shows a URL like `https://<PROJECT_NAME>.<REGION>.firebasedatabase.app/`   
It is the URL of the REST API to interact with the Firebase realtime database of the project.  
We can execute HTTP requests on it, by adding a relative path at the end.  
Firebase requires that we add the ".json" at the end to tell it the type.  
On a POST request, a new element in the items folder is created with a unique ID (name) :
```commandline
POST https://<PROJECT_NAME>.<REGION>.firebasedatabase.app/items.json
```

The `Rules` tab lets us define the READ and WRITE permissions on the database.
We can set the READ permission to `false` to receive an error on any GET request (to test error handling).  
In test mode, the permission is true for everyone during 30 days.

#### Firebase Authentication

Firebase also offers an authentication mechanism to create users and provide auth tokens.  
The simplest setup is to allow users to do anything they want if they are authenticated.  
We do not have ownership of resources here (we should add the owner in every resource to support it).  
We can set the Database rules to be :
```commandline
{
  "rules": {
    ".read": "auth != null",
    ".write": "auth != null"
  }
}
```

This is obviously not suitable for a real production env, but good enough to test the Angular app authentication.  
This will now send a 401 error to anyone hitting the endpoint without being authenticated.

In the `Authentication` section, click on the `Sign-in method` tab and enable "Email/Password".  
Once this is set up, we can see the users under the "Users" tab (originally empty).  
More info on the authentication endpoint URL by searching "Firebase Auth API" in Google.  
It is a dedicated API, completely unrelated with the real-time database.

Signup URL : `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=[API_KEY]`

The `API_KEY` placeholder is the web API key of the Firebase project, found in : Project Overview > Project Setup > Web API key


### Angular HTTP Module

In Angular, we need to add the `HttpClientModule` in the `app.module.ts` imports.  
Once imported, we can inject the `HttpClient` from the constructor of any component or service.  
This client offers a method per HTTP verb, for ex `http.post()` to generate a POST request.

These methods return Observable objects, and Angular actually sends the HTTP request only if it is subscribed to at least once.  
They are generic, so we can specify the type of objects we retrieve, to improve TS autocompletion and validation.  
Observable operators (map, filter...) can be used to pre-format the response to the type we want before we subscribe.  

```commandline
// POST
this.http.post(backendApiUrl, requestBody)
    .subscribe(responseData => {
      console.log(responseData);
    });

// GET to same endpoint with an observable operator to transform the response
this.http.get<Post>(backendApiUrl)
    .pipe(
      map(
        (responseData : any) => {   // transform JSON response into an array or Post objects
          const itemArray = [];
          for (key in responseData) {
            if (responseData.hasOwnProperty(key)) {
              itemArray.push({ ...responseData[key], id: key });
            }
          }
          return itemArray;
        }
      )
    )
    .subscribe(posts => {
      console.log(posts)
    });
```

We can see those requests being sent from the Chrome Developer tools, in the Network tab.  
There is an OPTIONS request checking if the POST method is allowed, followed by the POST request.  
If using Firebase, we can see that a table was created for the sent data in the Firebase Realtime Database.  
To handle errors in the HTTP request, we can provide a 2nd callback method to the `subscribe()` method :

```commandline
  this.get(url).subscribe(
    posts => { console.log(posts); },
    error => { console.log(error.message); }
  );
```

To pass custom headers, we have an optional config object in all http methods :

```commandline
  this.get(url, { headers: new HttpHeaders({ my-header: 'XXX' }) })
      .subscribe( responseData => { ... } );
```

To pass query parameters, we can either :
  - add it to the url : `https://myrecipes-4a862.firebaseio.com/items.json?print=pretty`
  - add it in the `params` field of the config object :
```commandline
  this.get(url, { params: new HttpParams().set('print', 'pretty') })
```

By default, Angular gives us the response body in our subscribe method.  
We can change this behavior to get the full response (with headers, response code) with the `observe` field of the config object.  
The different formats of response we can query are :

- `body` : body of the HTTP response (default)
- `response` : full HTTP response with body, headers, status code and URL.
- `events` : catches all messages going out an in, they are events with a `type` property (HttpEventType enum)  
             Type 0 is "Sent", type 4 is "Response" (HttpResponse received by `body` or `response`)  
             This is the most fine-grain level of observation.

```commandline
  this.get(url, { observe: 'response' })
      .subscribe( (response: HttpResponse) => { ... } );

  this.get(url, { observe: 'events' })
      .subscribe( event => {
         if (event.type == HttpEventType.Sent) {
           console.log('HTTP request was sent !');
         } else if (event.type == HttpEventType.Response) {
           console.log('HTTP response received : ');
           console.log(event.body);
         }
       });
```

By default, Angular converts the response body in JS object.  
We can change it by setting in the config object the field `reponseType` to `text` (`json` by default).  
Angular would then keep the received response as a string.


### HTTP Interceptors

So far we have set headers / body at HTTP request level in the post/get/delete methods of the http client.  
We may want to attach a header to all our requests (for ex an auth token).  
It would be annoying to add the logic in every HTTP request we create.  
Angular offers interceptors that intercept all requests before they are sent and can modify them before sending.

An interceptor is a service implementing the `HttpInterceptor` interface :

```commandline
  export class AuthInterceptorService implements HttpInterceptor {
    intercept(req: HttpRequest<any>, next: HttpHandler) {
      // clone our HTTP request (req is immutable)
      const myReq = req.clone({
          headers: req.headers.append('Auth', XXXX'}),     // if we want to add headers
          url: '<another URL>'                             // if we want to change the URL
      })
      // call the handler to let our modified request be sent
      return next.handle(myReq);
    }
  }
```

The interceptor needs to be added in the app.module.ts providers in a special way :

```commandline
  providers: [{
    provide:  HTTP_INTERCEPTORS,         // constant token to tell Angular it is an interceptor
    useClass: AuthInterceptorService,
    multi:    true                       // to not overwrite other interceptors if any
  }], ...
```

Angular will execute the interceptor on every HTTP request leaving the app.  
To restrict to only specific requests (GET for example), we need to add the logic inside the intercept method.

We can also intercept all HTTP responses coming in the app.
We use the same interceptor as above, but we add a pipe() to the returned observable.
This pipe always receive an "event" response type (the most granular) :

```commandline
    intercept(req: HttpRequest<any>, next: HttpHandler) {
      myReq = req.clone({ ... });
      next.handle(myReq).pipe(
        tap(
          (event : HttpEvent<any>) => {
            if (event.type === HttpEventType.Response) {
              console.log('The request response is :');
              console.log(event.body);
            }
          }
        )
      );
    }
```


### Authentication

Many apps use sessions for authentication.  
Session are an object that is created in the backend once the user enters his credentials.  
The backend then "knows" the client as long as the session is open.

Angular cannot use this mechanism, since frontend and backend are totally de-correlated.  
They only communicate via HTTP calls.

In Angular, once the client sends the credentials, the backend will generate a token from them, encode it with a secret key only the backend knows, and sends it to the Angular frontend.  
Every time the client sends a request that needs authentication, it will attach this token.  
The backend will then validate that it is correct, and execute the request.

The backend needs to have an HTTP endpoint to create a user, and to get a token for an existing user.  
We can use Firebase that provides this service out-of-the-box without writing a custom backend.

The Angular app must let the user create an account, login with an existing account or logout.  
It should then communicate with an auth service that handles the signup / login / logout.

To store the auth token so that it is read when the page reloads, we need persistent storage.  
Usual solutions are either cookies or local storage (an API controlled by the browser to store key/val pairs on the file system).

To store with local storage we need to convert the object to store into a string :

```commandline
localStorage.setItem('itemName', JSON.stringify(myObject));
```

It can be read at startup and removed on logout with :

```commandline
localStorage.getItem('itemName');
localStorage.removeItem('itemName');
```

We can see the content of local storage in the Chrome Developer tool : Application > Storage > Local Storage




## Angular Dynamic Components

We can load some components dynamically in our app, to create some modals or popups for example.  
One way to do it is to use `*ngIf` on a component with a backdrop, and to set the condition in code to show/hide the component.  
It is the easiest solution and it should be used when possible.

A more complex approach is to create the component programmatically.  
It must then be attached to the DOM and removed from the DOM from code manually.

This requires a method in the TS code to instantiate the dynamic component.  
We cannot just use `new MyComponent()` because Angular needs more than just instantiation.

We need to know where to create the component, which is given by a view container ref.  
It is obtained by creating a directive that injects publicly the `ViewContainerRef`.  

```commandline
@Directive({
  selector: '[appPlaceholder]'
})
export class PlaceholderDirective {
  constructor(public viewContainerRef: ViewContainerRef) {}
}
```

In the HTML template of the parent component, we create a `<ng-template>` tag where the dynamic component will be added.    
It is better than a `<div>` because it does not actually create an element in the DOM, but can be referenced.  
The `<ng-template>` tag must have the custom directive, so it can be located from the TS code :

```commandline
  <ng-template appPlaceholder></ng-template>
```

Then we can access the view container ref from the code via a member variable with the `@ViewChild` decorator :

```commandline
  @ViewChild(PlaceholderDirective, {static: false}) errorModalTemplate: PlaceholderDirective;
```

And use it to create a component dynamically :

```commandline
    const viewContainerRef = this.errorModalTemplate.viewContainerRef;
    viewContainerRef.clear();
    const modalRef = viewContainerRef.createComponent(AlertComponent);
```

For this to work, we need to let Angular know that this component will be created dynamically.  
This is automatic in Angular 9+, but older versions need to register it in the `entryComponents` property of the module :

```commandline
  entryComponents: [AlertComponent]
```

Then we can set the `@Input` and `@Output` bindings by using the `instance` of the new component ref.

```commandline
    modalRef.instance.message = message;                              // input
    this.modalCloseSub = modalRef.instance.close.subscribe(           // output close eventSubmitter
      () => {
        this.modalCloseSub.unsubscribe();
        viewContainerRef.clear();
      }
    );
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

### prettier

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

### loading.io

[loading.io](https://loading.io/css/) is a nice website offering some loading spinners (HTML and CSS).  
We can create a component with this copy/pasted code to have a ready to use spinner component.

