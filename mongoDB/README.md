# MongoDB Tutorial


## MongoDB Overview

- MongoDB is a noSQL, open source, distributed DB system
- A mongoDB server can contain multiple mongoDB databases
- MongoDB databases contain collections (noSQL equivalent of tables)
- MongoDB collections contain documents (noSQL equivalent of rows)
- MongoDB documents are JSON objects 
- MongoDB supports nested documents
- Unlike relational DBs using joins to combine data, MongoDB stores all together in a document
- More flexible and performant than relational SQL databases
- Atlas : : MongoDB databases on the cloud
- Compass : MongoDB GUI
- Stitch : Serverless MongoDB query API and functions


## MongoDB Installation and setup

From the [MongoDB website](https://www.mongodb.com/), download the Community Server.  
It offers a MongoDB database binary for Windows, MacOS, Ubuntu, Debian...  
Detailed documentation on the installation for each OS is available under : Resources > Server

we must install 2 components :
- `mongod` : binary to start a MongoDB server  
- `mongosh` : shell client to execute commands on a MongoDB database  

#### Local MongoDB server on Windows

Install the community server using the MSI wizard.  
This lets us create MondoDB as a service, so it starts `mongod` automatically at machine startup.  
MongoDB appears in the services screen (Launcher > Services) and can be started / stopped with :

```commandline
net start MongoDB
net stop MongoDB
```

The default MongoDB installation folder is `C:\Program Files\MongoDB\Server\6.0`  
This folder contains a `bin` folder containing `mongod`, a `data` folder where the DB will be created and a `log` folder to store MongoDB application logs.

To start the MongoDB server, double-click on the `mongod.exe` binary.  
It can also be started from the command line :
```commandline
.\bin\mongod.exe --dbpath data\ --logpath log\mongod.log
```
NOTE : this starts the MongoDB server without authentication, so anyone can perform any action in the database.

To start a shell client on the running MongoDB server, download the Mongo Shell from their website (zip folder).  
Extract the `mongosh.exe` binary to the above `bin` folder and double-click on it.

The Windows installer also lets us install the MongoDB Compass GUI to monitor MongoDB.

#### Local MongoDB server on MacOS

We can install MongoDB using homebrew :

```commandline
brew tap mongodb/brew
brew update
brew install mongodb-community@6.0
```

The MongoDB server can be started either manually with the `mongod` command, or as a homebrew service :

```commandline
brew services start mongodb-community@6.0
```

Then run a MongoDB shell client on the MongoDB server with the `mongosh` command.

#### MongoDB drivers

MongoDB offers drivers for most programming languages (Python, Node.js, Java, C++, ...).  
All available drivers are listed on the MongoDB website under : Resources > Drivers  

These driver allow programs to instantiate a MongoDB client to communicate with a running MongoDB server.  
They can perform the same actions as the `mongosh` shell client.


## MongoDB Commands

#### Databases and Collections

A MongoDB server contains multiple databases.  
Each database contains some collections.  
Databases and collections don't need to be explicitly created, they are created when they get used.

```commandline
show dbs                          Display all existing DBs
db                                Display the current DB
use zoo                           Use a DB (create it if not existing)
show collections                  Display all collections in the current DB
db.dropDatabase()                 Drop the current DB
db.animal.drop()                  Drop a collection in the current DB
db.stats()                        Display stats about the DB (# of collections and docs, size...)
db.animal.stats()                 Display stats about a collection (# of docs, size, average object size, indexes...)
db.createCollection('animal')     Create a collection in current DB
db.shutdownServer()               Shutdown the running MongoDB server
```

Collections are automatically created when used (for example when creating a document).  
The `createCollection()` method is used to specify some options, for example giving it a validator to control the schema.

We can create capped collections, that are fix-size collections with an optional max number of documents.  
They are sorted by insertion time, and delete older documents to make space for new inserted documents.  
They can be used for caching or logging when only recent data are useful to keep.
```commandline
db.createCollection("mycache", {capped: true, size: 10000, max: 3})
```



### Create documents

MongoDB documents must have a unique `_id` field.  
We can set it to a custom number or a string, as long as it is unique.   
When not provided, a default one of type `ObjectId` is generated automatically.

The `insertXxx()` methods take the data to insert, and an optional options parameter.

```commandline
db.animal.insertOne({name: 'Tom', age: 7})     Insert a document in a collection
                                               Create the collection if not existing
                                               Create a default _id field of type ObjectID
db.animal.insertMany([{a: 1}, {a: 2}])         Insert several documents in a collection

db.animal.insert({name: 'Jim'})               Deprecated - use insertOne() or insertMany() instead
```

MongoDB supports documents up to 16mb size, and up to 100 levels of nesting.  

```commandline
db.animal.insertOne({name: 'Tom', stats: {dex: 2, str: 3}})   Insert a document containing a nested document
```
`insertMany()` performs **ordered insertions**, that means that if one document fails to be inserted, the command will throw an error and not insert the next documents, but the documents before the failing one are inserted and not reverted.    
We can pass `{ordered: false}` in the 2nd parameter to insert all succeeding documents (even after the 1st failure).  
To rollback everything on failure, we can use MongoDB transactions.

MongoDB guarantees atomicity at document level : a document cannot be partially inserted.  
However there is no atomicity across documents by default, as montionned above with `insertMany()`.

### Get documents

Documents from a collection are retrieved with the `find()` method.  
It takes an optional filter parameter, and an optional options parameter. 

````commandline
db.animal.find()                       Get all documents in a collection
db.animal.find().pretty()              Get all documents in a collection and display indented JSON
db.animal.find({name:'Tom'})           Get all documents in a collection matching a filter
db.animal.findOne({name:'Tom'})        Get the first document in a collection matching a filter
db.animal.find({"stats.str": 3})       Filter on a nested field (require the double quotes)
````

#### Query Operators

We can use more complex filters by using MongoDB built-in query operators.

- comparison operators : `$eq`, `$ne`, `$lt`, `$lte`, `$gt`, `$gte`, `$in`, `$nin`
- logical operators : `$and`, `$or`, `$nor`, `$not`
- arithmetic operators: `$add`, `$subtract`, ...
- other operators : `$exists`, `$type`, `$jsonSchema`, `$regex`, `$expr`

```commandline
db.animal.find({age: {$lt: 13}})                      Find all documents with age < 13
db.animal.find({name:'Tom', age:12})                  Find with multiple conditions (AND operator)
db.animal.find({$and:[{name:"Tom"}, {age:13}]})       AND operator (alternative syntax)
db.animal.find({$or:[{name:"Tom"}, {age:13}]})        OR operator
db.animal.find({name:{$in:["Tom", "Coco"]}})          IN operator
db.animal.find({age: {$exists: true}})                EXISTS operator (can also use 0 or 1)
db.animal.find({age: {$type: "int"}})                 TYPE operator
db.animal.find({name: /^Zu/})                         Find all documents with name starting with "Zu" (regex)
db.animal.find({name: {$regex: "^Zu"}})               REGEX (alternative syntax)
db.animal.find({$expr: {$gt:["$weight", "$age"]}})    Compare 2 fields (note the $ prefix) 
db.animal.find({ $expr:
   {$gt: ["$age", {$subtract: ["$weight", 10]}]}})    Arithmetic operator in an EXPR
```

Note that the default "equality" filter can be used to check if a value is contained in an array.  
The `{names: "Tim"}` will return true if `"Tim"` is a value in the `names` field. 

The `find()` method does not return an array of documents, but a `Cursor` on the matching documents.  
If there are many documents in the result, only the first part will be included in the result, and we can type the `it` shell command to get the next part.  
When using a driver, we also get a cursor when querying data from the DB to avoid long wait and heavy network traffic.

We can call the `forEach()` method on the cursor to exhaust it and apply a function on each element :

```commandline
db.animal.find().forEach(
    (document) => { print(document.name + " is " + document.age + " years old") }
)
```

#### Projection

The 2nd argument of the `find()` method lets us specify a projection, i.e. the list of fields to retrieve.  
Only requested fields are sent by the MongoDB server, to avoid unnecessary data sent over the network.  
The `_id` field is included in every projection by default, but it can be explicitly excluded.

```commandline
db.animal.find({}, {name: 1, type: 1})            Get the name, type and ID of every document in the collection
db.animal.find({}, {name: 1, type: 1, _id: 0})    Get the name and type of every document in the collection
```

We can use the `$slice` operator in the projection to limit the number of elements in an array :
```commandline
db.animal.find({}, {name: 1, type: 1, food: {$slice: 2}})   // only show the first 2 elements in food
```

#### Examples

```commandline
// all animals eating mice with a food array of size different to 1
db.animal.find({$and: [{food: "mice"}, {food: {$not: {$size: 1}}}]})
```

### Update documents

The `updateOne()` and `updateMany()` methods let us modify one or several columns of the documents.  
Those methods take a filter parameter, an update parameter and an optional options parameter.  
The update parameter must contain an update operator, for example `$set` to set a field.  

The update operators are `$set`, `$min`, `$max`, `$inc`, `$mul`, `$rename`, `$unset` 

The `replaceOne()` method let us overwrite an entire document.  
It takes a filter parameter, the new document to use and an optional options parameter.  

```commandline
db.animal.updateOne({'name':'Tim'},{$set:{age:4}})            Set a field in one document
db.animal.updateOne({'name':'Tim'},{$set:{age:4, str:12}})    Set multiple fields in one document
db.animal.updateMany({'name':'Tim'},{$set:{age:4}})           Set a field in multiple documents

db.animal.replaceOne({name:'Tom'},{name:'Tim'})               Replace a document

db.animal.update({'name':'Tim'},{$set:{age:4}})               Deprecated - use updateOne() or updateMany() instead
```

We can use other update operators :

```commandline
db.animal.updateOne({'name':'Tim'}, {$inc:{age:2}})           Increment a field by 2 in one document
db.animal.updateOne({'name':'Tim'}, {$mul:{age:2}})           Multiply a field by 2 in one documents
db.animal.updateOne({'name':'Tim'}, {$min:{age:20}})          Set the age in one document to min(age, 20)
db.animal.updateOne({'name':'Tim'}, {$unset:{age:""}})        Unset a field (the value is ignored)
```

To insert the document in case there is no match, we can pass the `upsert` flag as a 3rd parameter.  
Mongo DB will create a document with both the filter and the set fields.
```commandline
db.animal.updateOne({'name':'Claw'}, {$set: {age: 12, type: "Tiger", food:["chicken"]}}, {upsert: true})
```


### Delete documents

The `deleteOne()` and `deleteMany()` methods both accept a filter parameter.  
That filter can use the same query operators as for the `find()` method.

```commandline
db.animal.deleteOne({type: "Monkey"})     Delete at most one document matching a filter 
db.animal.deleteMany({type: "Monkey"})    Delete all documents matching a filter
db.animal.deleteMany({age: {$lt: 10}})    Delete all documents matching a filter with an operator
db.animal.deleteMany({})                  Delete all documents in the collection

db.animal.remove()                        Deprecated - use deleteOne() or deleteMany() instead
```


## MongoDB Schemas and Structure

MongoDB is schemaless and does not enforce any common structure between documents within a collection.  
However, we often want to enforce a common structure to all documents in a collection.  
For example, all animals in a collection should have a `name` and a `type`, and optionally an `age` and a `subtype` fields.

#### MongoDB data types

- String
- Boolean
- Numbers : 
  - NumberInt (32-bits integer)
  - NumberLong (64-bits integer)
  - Double (64-bits decimal, default number type in MongoDB shell that is based on JS)
  - NumberDecimal (128-bits decimal, used for high precision calculation)
- ObjectID (Mongo ID, guaranteed to be ordered)
- ISODate (date)
- Timestamp : unique number, used to generate the ObjectID, can be called with `new Timestamp()`
- Object (for nested documents)
- Array
- Null
- Binary Data
- Code (JS)

We can get the type of a field with the `typeof` operator :

```commandline
typeof db.animal.findOne().name                Get the type of the name property of the document
```

MongoDB shell is based on Javascript, so by default all numbers are stored as 64-bits double numbers.  
We can force another numeric type by using its constructor, for example `NumberInt("12")` for an integer field.
The constructor takes the value as a string, to prevent JS to convert it to a double first.

NOTE : MongoDB does not throw any exception in case of number overflow, it just saves an incorrect number !


#### Relations between MongoDB documents

The ways to represent relations between MongoDB documents are :

- **Nested documents**  
  This makes sense when the nested object is tightly related to the parent object.  
  That is often a good approach for 1-to-1 or 1-to-N relations.  
  For example, an address could be represented as a nested document inside a person document. 


- **ID reference**  
  A different collection is used to store the other document, and its `_id` field is stored by the parent.  
  This is the best approach for N-to-N relations, as it avoid unnecessary duplication.  
  For example, favorite books could be stored as an ID array in a person documents.


- **Dedicated collection for the relation**  
  When the relation itself does represent something useful for the business, it can have its own collection.  
  This is useful for some N-to-N relations.  
  For example, if we have a `customers` collection and a `products` collection, we may want to store the orders in a dedicated `orders` collection referencing both a customer and a product by their `_id` field.  

#### Aggregate

When data are split across multiple collections, we can use the `aggregate()` method when we query the data to enrich the documents with the data from the referenced collection (equivalent to JOIN in SQL) :

```commandline
db.animal.aggregate([{
    $lookup: {                                Lookup operator to join collections
        from: "employee",                     Name of the other collection to join
        localField: "caretaker",              Name of the reference field in the current collection
        foreignField: "_id",                  Name of the reference field in the joined collection
        as: "caretakerInfo"                   Nmae of the field to store the result into
    }
}])
```

#### Schema Validation

We can create a schema validation for a given collection.  
This validation specify a validation level (`strict` for all insert/update, `moderate` for insert and valid document update).  
It also specifies a validation action (`error` to prevent the insert/update, `warn` to log a warning message).

For example, we can create an `employee` collection with a custom JSON schema.  
That schema forces to have a `name` and a `job` field of type string.

```commandline
db.createCollection("employee", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["name", "job"],
      properties: {
        name: { bsonType: "string", description: "employee's full name" },
        job: { bsonType: "string", description: "employee's official job title" },
      }
    }
  }
})
```

When trying to insert a document missing the `job` field for example, a `MongoServerError` is thrown and the document is not inserted.

We can update the collection's configuration once it is already created with the `runCommand()` method.  
We can for example change the validation action to `warn` (it is `error` by default).  
In that case, invalid insert/update operations are accepted, but they are logged in the MongoDB log file.

```commandline
db.runCommand({
  collMod: "employee",
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["name", "job"],
      properties: {
        name: { bsonType: "string", description: "employee's full name" },
        job: { bsonType: "string", description: "employee's official job title" },
      }
    }
  },
  validationAction: "warn"
})
```

## MongoDB Compass GUI

The MongoDB Compass GUI lets us visualize the data in the DB, and interact with it graphically.  
We can have multiple connections in Compass, it will open one window per connection.  
By default, it connects to `localhost` on port `27017`, the default configuration of the MongoDB server.  

Most actions that can be performed in the MongoDB shell can also be performed in Compass, for example :

- create / delete a database
- create / delete a collection
- create schema, validations, aggregations, indexes for a collection
- Run a query in a collection
- insert documents in a collection (manual or file import)
- edit or delete existing documents

![Compass Image](./images/compass.png)


## MongoDB Command-line Database Tools

From MongoDB website, we can install MongoDB Command-line tools.  
On Windows for example, we can downmload the ZIP and copy all binaries to the main MongoDB bin folder.

#### mongoimport

This is a binary to import data from a JSON file into a collection of a MongoDB database.  
It will create the database and/or the collection if needed.

```commandline
$>  mongoimport.exe ./food.json -d zoo -c food --jsonArray --drop

2023-02-28T23:16:46.848+0900    connected to: mongodb://localhost/
2023-02-28T23:16:46.850+0900    dropping: zoo.food
2023-02-28T23:16:46.866+0900    3 document(s) imported successfully. 0 document(s) failed to import.
```
- `--jsonArray` : insert multiple values as an array
- `--drop` : drop the current content of the collection if any


## Querying Arrays

#### Array of basic types

For array fields of basic types (non-document), we can check the exact match of a value, the inclusion of a field or the size :
```commandline
db.animal.find({ food: ["seeds", "fruits"] })           Array equality
db.animal.find({ food: "seeds" })                       Item inclusion (same syntax as simple field)
db.animal.find({ food: {$all:["seeds", "nuts"]} })      Multiple items inclusion
db.animal.find({ food: {$size:3} })                     Array size
```

#### Array of documents

For array fields of documents, we can check or update the values inside the array.

```commandline
db.shops.insertMany([
{name: "Shop1", movies:[{title: "Movie1", year: 1998}, {title: "Movie2", year: 2003}]},
{name: "Shop2", movies:[{title: "Movie1", year: 1998}, {title: "Movie3", year: 2004}]},
{name: "Shop3", movies:[{title: "Movie3", year: 2004}]}
])
```

We can reference the fields of the array items as it they were fields of the array itself.  
For example if a `movies` field is an array of documents with a `title` and a `year`, we can get all shops having a film with a title of `Movie3` :
```commandline
db.shops.find({"movies.title": "Movie3"})
```

We can use the `$size` operator to match an exact size (cannot combine it with `$gt`) :
```commandline
db.shops.find({"movies": {$size: 2}})
```

To select documents with an array field containing a given list of values (no matter the order) we use `$all` :
```commandline
db.animal.find({food: {$all: ["eggs", "mice"]}})
```

To apply some filtering on objects inside an array, we can use the `$elemMatch` operator :
```commandline
db.shops.find({"movies": {$elemMatch: {title: "Movie3", year: 2004}}})
```

When we want to update an element inside an array field, we can use `$elemMatch` in the filter, and the `$` syntax in the update parameter to reference the first matched item in the array :
```commandline
db.shops.update( {"movies": {$elemMatch: {title: "Movie3", year: 2004}}},
                 {$set: {"movies.$.recent": true}} )
```

We can update all elements inside an array with the `$[]` syntax in the update parameter, to references all elements inside the array :
```commandline
db.shops.updateMany( {name: "Shop1"},
                     {$set: {"movies.$[].inStock": false}} )
```

We can also update only some specific items inside an array, by using the `$[el]` syntax.  
`el` is a variable name that we can apply conditions on in the options parameter in the `arrayFilters` field :
```commandline
db.shops.updateMany( {},
                     {$set: {"movies.$[el].recent": true}},
                     {arrayFilters: [ {"el.year": {$gt: 2000}} ]} )
```

Elements can be added in an array field with the `$push` operator.  
To add only if the element is not already in the array, we can use the `$addToSet` operator instead.  
To add multiple elements at once, we combine it with the `$each` operator :
```commandline
db.shops.updateOne( {name:"Shop1"},
                    {$push: {"movies": {title: "Movie4", year: 2010}}} )
db.shops.updateOne( {name:"Shop1"},
                    {$push: {"movies": {$each: [ {title: "Movie5", year: 2011},
                                                 {title: "Movie6", year: 2012} ]}}} )
```

To remove all elements matching a filter from an array field, use the `$pull` operator.
To remove the first or last element of the array, we can use `$pop` instead with value 1 or -1.

```commandline
db.shops.updateOne( {name: "Shop1"},
                    {$pull: {movies: {year: {$gt: 2000}}}} )

db.shops.updateOne( {name: "Shop1"},
                    {$pop: {movies: -1}} )     // pop the last element
```


## MongoDB Cursors

The `find()` method returns a cursor that lets us ask for the next batch of results.  
The MongoDB shell automatically displays requests the first batch to display the first 20 documents.  
It provides the `it` command to request the next batch.  
When using a MongoDB driver, we need to handle that cursor manually to ask for result batches.

The MongoDB shell accepts JS-like syntax, so we can store a cursor in a variable.  
Some cursor methods allow us to cout, sort, iterate on documents, limit the output and skip some documents (useful for pagination) ...

```commandline
const cursor = db.animal.find()    // cursor on all documents of the collection
cursor.next()                      // first document of the cursor
cursor.next()                      // second document of the cursor

cursor.count()                     // total number of documents in the cursor 

cursor.forEach(                    // iterate through all documents in the cursor
  doc => { printJson(doc) }
)

db.animal.find().sort({"age": 1})    // sort the results of a cursor
                                     // must be applied before getting any batch

cursor.limit(10)                     // get only the first 10 documents
cursor.skip(10)                      // start getting documents after an offset
```


## MongoDB Indexes


Indexes speed up the search for specific documents (used by find, update and delete operations).  
When a collection has no custom index, MongoDB scans the entire collection every time it looks for documents.  
An index is a structure that can be created to enrich a collection, it is an ordered list of one or more field(s) of the collection.  
Every item in the index has a pointer to the referenced document in the original collection.  
When searching for a document with a specific value for this indexed field, MongoDB can then do an index scan, and only check the documents with this value for this field without scanning other documents.

Indexes also speed up the `sort()` operation, if the indexed fields match the sort criteria.

Indexes speed up the find operations, but they take space on disk, and they slow down insert, update and delete operations, as the indexes must also be updated during each of these operations.  
For queries that match the entire collection, using an index is slower than a full scan, as it adds the overhead of going through the index.


#### MongoDB Search Strategy

We can get some info on how MongoDB searches documents in a collection with the `explain()` method.  
It shows the `winningPlan` with a stage set to `COLLSCAN`, which means it does not use an index.  
With no existing index other that the default `_id_` one, `COLLSCAN` is the only option MongoDB can use.

For example, in the `persons` collections imported from `data/persons.json` file :

```commandline
db.persons.explain().find({"dob.age": {$gt: 60}})
db.persons.explain("executionStats").find({"dob.age": {$gt: 60}})    // more stats on excution time
```

#### Simple Index

A simple index is built on a single-value field of the documents in a collection.  
We can create an index on the `dob.age` field and see that it was created and is used :

```commandline
db.persons.createIndex({"dob.age": 1})               // create index
db.persons.getIndexes()                              // list existing indexes

// much quicker than without index, and now uses IXSCAN stage (index scan)
db.persons.explain("executionStats").find({"dob.age": {$gt: 60}})

db.dropIndex({"dob.age": 1})                        // drop index by definition
db.dropIndex("dob.age_1")                           // drop index by name
```


#### Compound Index

We can create a compound index that indexes a collection on multiple fields.   
The order of the field is important, as a compound index can be used as an index of the first indexed field alone, but not on the 2nd indexed field alone.

```commandline
// compound index on age and gender
//    - speed up queries on (age, gender)
//    - speed up queries on age
//    - DOES NOT SPEED UP queries on gender
db.persons.createIndex({"dob.age": 1, genre: 1})
```


#### Unique Index

We can create a unique index by configuring the index with a 2nd parameter.  
In that case, unicity is checked at every insert and the insertion throws an error when it would create a duplicate.
```commandline
db.person.createIndex({phone: 1}, {unique: true})
```


#### Partial Index

We can create a partial index that only indexes the part of the collection specified by a given filter.  
This saves space in memory if we know only a given part of the collection is often accessed.
```commandline
db.persons.createIndex({"dob.age": 1}, {partialFilterExpression: {"dob.age": {$gt: 50}}})
```


#### Index with TTL (Time To Live)

We can create an index with TTL by indexing a collection on a Date field, and setting an expiration time.  
When we insert a document in the collection, it will be added to the collection, and then removed automatically after the expiration. 

```commandline
db.sessions.createIndex({createdAt: 1}, {expireAfterSeconds: 10})    // create index with TTL
db.sessions.insertOne({name: "bbb", createdAt: new Date()})          // insert a document
db.sessions.find()                                                   // the document exists
db.sessions.find()                                                   // 10s later, the document is removed 
```


#### Multi-key Index

We can create a multi-key index by indexing a collection on an array field.  
For each document of the collection, MongoDB creates one entry in the index per value in the array.  
It means that the same document is referenced by multiple entries in the index (every entry that is in the array).  
This can be useful sometimes, but it creates a bigger index than single-field indexes, since each document is referenced multiple times.


#### Text Index

MongoDB also supports the creation of a text index on a text field.  
It splits the field value of each document into meaningful words (no space, punctuation, meaningless words...).  
It then creates a multi-key index on this array of meaningful words in lower-case.

```commandline
db.products.insertMany([
    { name: "Computer",   description: "high-tech computer with new-gen keyboard" },
    { name: "T-shirt",    description: "black T-shirt with a picture" },
    { name: "Smartphone", description: "latest high-tech phone" } ])

db.products.createIndex({ description: 1 })            // normal index (exact match)
db.products.createIndex({ description: "text" })       // text index
```

There can be only 1 text index for a given collection.  
To retrieve the documents matching a given text token, we do not need to specify the indexed field, instead we use the `$text` operator : 

```commandline
db.products.find({$text: {$search: "high-tech"}})         // 2 matches
db.products.find({$text: {$search: "high"}})              // 2 matches
db.products.find({$text: {$search: "HIGH"}})              // 2 matches (case-insensitive)
db.products.find({$text: {$search: "with"}})              // 0 match (meaningless word)
db.products.find({$text: {$search: "black phone"}})       // 2 matches ("black" in a doc, "phone" in another)
db.products.find({$text: {$search: "high-tech -phone"}})  // 1 match (exclude "phone") 
```

We can  add a match score to each result document of a text query by using the `$meta` operator on the built-in `textScore`.  
We can sort by that `score` field to order results by relevance :
```commandline
db.products.find({$text: {$search: "high-tech phone"}}, {score: {$meta: "textScore"}})
           .sort({score: 1})
```

We can specify multiple fields for the text index.  
Those fields will all be split to meaningful tokens and used for the text index of the collection.

```commandline
db.products.createIndex({name: "text", description: "text"})
```

We can specify the index language at creation, it will help MongoDB know the list of meaningless words.  
The fields used in a text index can also have different weights, used by MongoDB to calculate the match score.

```commandline
db.products.createIndex({description: "text"}, {default_language: "french"})
db.products.createIndex({name: "text", description: "text"}, {weight: {name: 2, description: 1}})
```

#### Index Creation

Indexes can be created either at the foreground or in the background.  
When created at the foreground, the collection is locked during that time.  
When created in the background, the collection is not locked, but the index creation takes longer.  
This is a safer approach for operation-heavy production MongoDB databases.

```commandline
db.products.createIndex({description: "text"}, {background: true})
```

## Geospatial Queries

#### Latitude and Longitude

A position on Earth is fully determined by its latitude and its longitude.

The **latitude** determines the north/south distance of a point from the equator plane.  
It varies from -90° (south pole) to 90° (north pole).  
The horizontal imaginary lines at a same latitude are called latitude lines.

Reference latitude lines are :
- Equator (latitude = 0°) : line perpendicular to the Earth's rotation axis, splitting it into 2 hemispheres 
- Tropic of Cancer (latitude = 23°26') : north-most line where the Sun can be directly overhead (during June solstice)
- Tropic of Capricorn (latitude = -23°26') : south-most line where the Sun can be directly overhead (during December solstice)
- Arctic Circle (latitude = 66°34') : south-most line where the sun does not rise all-day during the December solstice
- Antarctic Circle (latitude = -66°34') : north-most line where the sun does not rise all-day during the June solstice

The **longitude** determines the west/east distance of a point from the prime meridian (Greenwich).  
It varies from 0° (prime meridian) to 180° (ante-meridian), either west or east.  
The vertical imaginary lines at a same longitude are called longitude lines, or meridians.  
The Greenwich meridian is the used as the reference timezone (GMT : Greenwich Mean Time).

#### GeoJSON format

MongoDB supports the GeoJSON object format, to represent geographic structures and locations.  
GeoJSON objects include `Point`, `MultiPoint`, `LineString`, `MultiLineString`, `Polygon`, `MultiPolygon`...

GeoJSON objects allow to store geographical objects in MongoDB (like restaurants, streets, places to visit...).  
When selecting a place in Google Maps, the URL (or right-click) shows the latitude and longitude.

A GeoJSON object in MongoDB is a document with a `type` field and a `coordinates` array field.  
The coordinates of a point must be the longitude, then the latitude (opposite order from Google Maps).

```commandline
db.places.insertMany([{ name: "The Great Pyramid of Giza",
                        location: {type: "Point", coordinates: [31.13116, 29.9782653]} },
                      { name: "Eiffel Tower",
                        location: {type: "Point", coordinates: [2.2916715, 48.8577166]} },
                      { name: "Arc de Triomphe",
                        location: {type: "Point", coordinates: [2.2973108, 48.8638763]} },
                      { name: "Louvre Museum",
                        location: {type: "Point", coordinates: [2.3167021, 48.8557928]} },
                      { name: "Montparnasse Tower",
                        location: {type: "Point", coordinates: [2.3186794, 48.8550403]} } ])
```

#### GeoJSON Operators

MongoDB offers some operators to query GeoJSON data like the `$near` operator.  
It uses the `$geometry` to specify the origin point or polygon we are comparing to.  
The max/min distance can be set with the `$maxDistance` and `$minDistance` operators (to decide what "near" means in meters).  

To use the `$near` operator, we need to create a 2D-sphere index on the location field.  

```commandline
// create a 2D-sphere index
db.places.createIndex({location: "2dsphere"})

// return all places sorted from the closest to the furthest from a point (Trocadero Square)
db.places.find({location: {$near: {$geometry: {type: "Point", coordinates: [2.2942828, 48.860679]} }}})

// find the places within a given range from a point (Trocadero Square)
db.places.find({location: {$near: {$geometry: {type: "Point", coordinates: [2.2942828, 48.860679]}, $maxDistance: 1000 }}})
```

We can use the `$geoWithin` operator to find the documents with coordinates with a given polygon.  
It usually takes a `$geometry` value containing a GeoJSON object, but it can also use the `$centerSphere` operator to find documents in a given radius.  
The `$centerSphere` operator takes the sphere center and radius, expressed in radians (distance / Earth radius).  

```commandline
// find all places inside Paris
const p1 = [2.256204, 48.844023]   // bottom-left
const p2 = [2.363241, 48.820309]   // bottom-right
const p3 = [2.406938, 48.880799]   // top-right
const p4 = [2.326965, 48.902211]   // top-left
db.places.find({location: {$geoWithin: {$geometry: {type: "Polygon", coordinates: [[p1, p2, p3, p4, p1]]}}}})

// find all places within a 1.8km radius from a point (Trocadero Square)
db.places.find({location: {$geoWithin: {$centerSphere: [[2.2942828, 48.860679], 1.8/6378.1 ]}}})
```

We can also use the `$geoIntersects` operator to perform the opposite operation : all documents have a polygon field, and we want to find all documents which polygon contains a given point.

```commandline
// create a "cities" collection with Paris and Tokyo
const t1 = [139.621526, 35.624110]
const t2 = [139.789462, 35.537991]
const t3 = [139.847174, 35.721939]
const t4 = [139.692932, 35.723849] 
db.cities.insertMany([ {name: "Paris", area: {type: "Polygon", coordinates: [[p1, p2, p3, p4, p1]]}},
                       {name: "Tokyo", area: {type: "Polygon", coordinates: [[t1, t2, t3, t4, t1]]}} ])
db.cities.createIndex({location: "2dsphere"})

// find in which city a given point is (Trocadero Square)
db.cities.find({area: {$geoIntersects: {$geometry: {type: "Point", coordinates: [2.2942828, 48.860679]} }}})
```

## MongoDB Aggregation Framework

The Aggregation Framework exposes the `aggregate()` method, an alternative to `find()` for more complex queries.  
It allows to build a query as a pipeline of stages to retrieve data in the desired format.  
It includes filtering, sorting, grouping, projections, join with other collections, ...  

The first stage in the aggregation pipeline receives as input the documents from a MongoDB collection.  
Each following stage receives as input the output of the previous stage, and returns an iterator on the result  
The MongoDB documentation provides the exhaustive list of available stages.

The `aggregate()` method takes as a parameter an array of successive stages.  
The first stage executes on the collection, and can take advantage of indexes (to filter or sort).

#### $match stage

`$match` is the filtering stage, it accepts the same type of filter object than the `find()` method.  

```commandline
db.persons.aggregate([
  {$match: {gender: "female" }}
])
```

#### $group stage 

`$group` allows to group input documents by one or more fields.  
The value by which we group is defined in the `_id` field, it can be a field or an object.  
Some accumulators are used to get aggregated indicators on grouped documents, like `$max`, `$min`, `$avg`, `$count` ...
```commandline
db.persons.aggregate([
  {$match: {gender: "female" }},
  {$group: { _id: { state: "$location.state"}, avgAge: {$avg: "$dob.age"}, totalPersons: { $count: {} } }}
])
```

#### $bucket and $bucketAuto stages

We can organize the data into buckets on a given numeric field with the `$bucket` stage.  
It is similar to the `$group` stage, but it groups documents on a range of values instead of an exact value.  
The output can be specified with the same grouping operators as the `$group` stage.  
The `$bucketAuto` stage can be used instead to tell MongoDB how many buckets we want and let it figure out the boundaries.
```commandline
// buckets with manually defined boundaries
db.persons.aggregate([
  {$bucket: {
    groupBy: "$dob.age",
    boundaries: [0, 20, 40, 60, 80, 100, 120],
    output: {
      count: {$count: {}},
      average: {$avg: "$dob.age"}
    }
  }}
])

// bucket with automatic boundaries
db.persons.aggregate([
  {$bucketAuto: {
    groupBy: "$dob.age",
    buckets: 5,
    output: {
      count: {$count: {}},
      average: {$avg: "$dob.age"}
    }
  }}
])
```

#### $sort stage

`$sort` lets us sort the input documents by a criteria.  
It does not need to apply on the original collection, it can be used after a `$group` stage for example.
Like in the `find()` method, the sort can be applied to one or more field in ASC or DESC order.

```commandline
db.persons.aggregate([
  {$match: {gender: "female" }},
  {$group: { _id: { state: "$location.state"}, totalPersons: { $count: {} } }},
  {$sort: {totalPersons: -1}}
])
```

#### $project stage

The `$project` stage is similar to the projection in the `find()` method.  
It lets us reformat the data, by selecting fields to include or exclude.  
It also lets us create new fields and specify how to build them from the document received in input.

```commandline
// reformat the documents to show a full name with the last name and first letter of the first name in upper case
db.persons.aggregate([{
  $project: {
    _id: 0,
    gender: 1,
    fullName: {
      $concat: [
        {$toUpper: "$name.last"},
        " ",
        {$toUpper: { $substrCP: ["$name.first", 0, 1] }},
        {$substrCP: ["$name.first", 1, {$subtract: [ {$strLenCP: "$name.first"}, 1 ]}] }
      ]
    }
  }
}])
```


To convert a value to a given type we can use the conversion operator `$toInt`, `$toDouble`, `$toString`, `$toDate` ...   
The `$convert` operator is more generic, and allows to specify a value when the field is missing or the conversion fails.

We can also create a GeoJSON in the `$project` step, by creating an object with valid `type` and `coordinates` fields.
```commandline
// create a GeoJSON location field inside the projection
db.persons.aggregate([{
  $project: {
    email: 1,
    name: 1,
    age: "$dob.age",
    location: {
      type: "Point",
      coordinates: [
        {$toDouble: "$location.coordinates.longitude"},
        {$toDouble: "$location.coordinates.latitude"}
      ]
    }
  }
}])
```

The year of a date can also be extracted with the `$isoWeekDate` operator.

#### $skip and $limit stages

We can skip some documents or limit to N documents with the `$skip` and `$limit` pipeline stages.  
Combining a `$sort` stage with a `$skip` and a `$limit` stage can be used to implement pagination.
```commandline
// get the 4th page of 10 documents sorted by name
db.persons.aggregate([
  { $project: { name: {$concat: ["$name.first", " ", "$name.last"]}, gender: 1}},
  { $sort: {name: 1} },
  { $skip: 30 },
  { $limit: 10 }
])
```

#### $out stage

We can save the result of the pipeline to a collection with the `$out` stage :
```commandline
// save the output to a "names" collection
db.persons.aggregate([
  { $project: { name: {$concat: ["$name.first", " ", "$name.last"]} }},
  { $out: "names" }
])
```

#### $geoNear stage

The `$geoNear` pipeline stage can be used to return documents near to a given GeoJSON object.  
It is the equivalent of the `$near` GeoJSON query operator, but used as a pipeline stage.   
It applies only on a GeoJSON field of the input documents.  
`$geoNear` MUST be the first stage in the pipeline, because it needs to use an existing geo-index on the collection.  
It requires a `near` object to specify the source, a `maxDistance` field to specify the radius, and a `distanceField` field to specify the name of the field in the output that will contain the calculated distance.

```commandline
// save the person positions in a new collection using a GeoJSON point
db.persons.aggregate([
  { $project: { name: {$concat: ["$name.first", " ", "$name.last"]},
                pos: {type: "Point", coordinates: [{$toDouble: "$location.coordinates.longitude"},
                                                   {$toDouble: "$location.coordinates.latitude"}]}} },
  { $out: "positions" }
])

// create a geo index on the new collection
db.positions.createIndex({pos: "2dsphere"})

// find positions in a 500km radius from a given point
db.positions.aggregate([
  { $geoNear: {
    near: { type: "Point", coordinates: [43, 16 ]},
    maxDistance: 500000,
    distanceField: "distance"
  } }
])
```


### Aggregation with arrays

The examples use the data in the `friends.json` file :
```commandline
.\mongoimport.exe -d demo -c friends .\data\array-data.json --jsonArray
```

In a `$group` stage, we can create an array containing a field value for all documents in the group with the `$push` operator.  
If we want no duplicate value in the resulting array, we can replace `$push` by the `$addToSet` operator.

```commandline
// create an array of names of persons in each group (potential duplicates)
db.friends.aggregate([
  {$group: { _id: "$age", names: {$push: "$name"} }}
])

// create an array of names of persons in each group (no duplicates)
db.friends.aggregate([
  {$group: { _id: "$age", names: {$addToSet: "$name"} }}
])
```

The `$unwind` stage can be used to split an array field (1 to N stage).  
For each value in this array field, it adds to the pipeline a new document with the unwind field equal to that value (no longer an array), and every other field identical to the input document.  
All output documents resulting from the same input document have the same `_id` value.

```commandline
// split the hobbies to create one document per (friend, hobby) pair
db.friends.aggregate([{ $unwind: "$hobbies" }])
```

We can keep only the first N elements of an array with the `$slice` operator.  
To get the last N elements, we can use a negative value as 2nd parameter.  
To get a slice of N items starting from position K, we can give an additional parameter before the number of elements to keep.
```commandline
// keep the first 2 scores
db.friends.aggregate([
  {$project: {name: 1, scores: {$slice: ["$examScores", 2]}}}
])

// keep 2 element starting from index 1 (skip the first)
db.friends.aggregate([
  {$project: {name: 1, scores: {$slice: ["$examScores", 1, 2]}}}
])
```

To get the length of an array, we can use the `$size` operator :
```commandline
db.friends.aggregate([
  {$project: {name: 1, scoresCount: {$size: "$examScores"}}}
])
```

We can apply a filter to elements in an array with the `$filter` operator.  
It specifies the input array, a local name for the variable, and a condition that can use the variable.  
The local variable is referenced with a `$$` prefix (a single `$` would reference a field value from the pipeline document)
```commandline
db.friends.aggregate([
  {$project: {
    name: 1,
    goodScores: {
      $filter: {input: "$examScores", as: "item", cond: {$gt: ["$$item.score", 60]}}
    }
  }}
])
```

Example of combination of multiple stages :
```commandline
// get each friend ranked by their best score 
db.friends.aggregate([
  {$unwind: "$examScores"},                               // split all the scores
  {$project: {name: 1, score: "$examScores.score"}},      // keep only the score 
  {$group: {_id: "$name", score: {$max: "$score"}}},      // group by person to get the max
  {$sort: {score: -1}}                                    // sort in descending order
])
```

## Transactions

MongoDB supports transactions, so a group of operations either all succeed or are all rolled back.  
A session needs to be created, then a transaction is started in this session.  
Operations can be performed from the collections extracted from the session.  
The transaction can then be either committed or aborted.

```commandline
// create a player and characters referencing this player
use game
db.players.insertOne({_id: "1234", name: "Tom"})
db.characters.insertMany([{race: "elf", lvl: 12, playerId: "1234"},
                          {race: "orc", lvl: 7, playerId: "1234"}])

// create a session to group queries in a transaction
const session = db.getMongo().startSession()
const playersCollection = session.getDatabase("game").players
const charactersCollection = session.getDatabase("game").characters
session.startTransaction()

// perform queries in a single transaction
playersCollection.deleteOne({_id: "1234"})
charactersCollection.deleteMany({playerId: "1234"})

// commit or abort the transaction
session.commitTransaction()
session.abortTransaction()
```


## MongoDB Security

### Authentication and Authorization

MongoDB uses a role-based access control.  
Roles define a set of privileges, which are specific actions on specific resources.  
Users are assigned some roles, and are granted all privileges defined by these roles.

We may want for example 3 types of roles :
- Administrator role, allowed to manage users and the databases schemas
- Developer role, allowed to insert/edit/delete/fetch business tables in a given database
- Data Scientist role, allowed to fetch data from business tables

MongoDB ships with built-in roles :
- Database User roles : `read` and `readWrite`
- Database Admin roles : `dbAdmin`, `userAdmin` and `dbOwner`
- All Database Roles : `readAnyDatabase`, `readWriteAnyDatabase`, `userAdminAnyDatabase`, `dbAdminAnyDatabase`
- Cluster Amin roles
- Backup and Restore roles : `backup` and `restore`
- Superuser roles : `root`, `userAdmin` (in `admin` DB)

It is also possible to create custom roles, for example for give granular permission at collection level.

#### MongoDB Authentication setup

We can enable authentication in MongoDB with the `--auth` parameter in the `mongod` MongoDB server command. This indicates to MongoDB that users must be authenticated before they can perform any action.

With the `mongosh` client, we can connect to the MongoDB server without credentials in the command line.  
However, unauthenticated users connecting to the MongoDB server cannot perform any action. 

The only exception to that rule is when we connect the first time to a MongoDB server that has no user.  
In that case, we are allowed to access the built-in `admin` database, and create an administrator  user with user-level permissions : 
```commandline
use admin
db.createUser({user: "myusername", pwd: "mypassword", roles: ["userAdminAnyDatabase"]})
db.auth({user: "myusername", pwd: "mypassword"})
```

To authenticate as this user, we can either call the `db.auth()` command in the database where this user was created, or specify its credentials and its authentication database in the parameters of the MongoDB client command line :
```commandline
.\mongosh.exe -u myusername -p mypassword -authenticationDatabase admin
```

#### User management

This administrator user created above only has the `userAdminAnyDatabase` role.  
This means that he cannot execute any CRUD operations on databases, but he can create users and grant them permissions.

Users are created in a given database, and their permissions are restricted to that database.  
The administrator can access a database and create users in it :
```commandline
use shop
db.createUser({user: "dev1", pwd: "dev1pwd", roles: ["readWrite"]})
```

Now if we authenticate as this new user, we can perform any CRUD operation on any collection of this database.
```commandline
db.auth({user: "dev1", pwd: "dev1pwd"})
db.products.insertOne({name: "Guitar", price: 149.99})
```

A user is created in a single database, but can have permissions on multiple databases.  
To grant permissions on another database to a user, the administrator can run the `updateUser()` method.
```commandline
// authenticate as the administrator
use admin
db.auth({user: "myusername", pwd: "mypassword"})

// update the dev1 user in his database and give him access to the "blog" database
use shop
db.updateUser("dev1", {roles: ["readWrite", {role: "readWrite", db: "blog"}]})
```

We can see the currently authenticated user and its permissions with :
```commandline
db.runCommand({connectionStatus: 1})
```

To see the details of a user in a database, we can also use the `getUser()` method :
```commandline
use shop
db.getUser("dev1")
```

### MongoDB Encryption

Data sent from a MongoDB client (shell or driver) can use TLS/SSL encryption protocol for data in transit.  
This requires to setup a public/private key pair and generate a certificate of authority.  
It can be done with OpenSSL for a test database.  
The `mongod` server and the MongoDB client must specify the SSL configuration in their command line parameters.

MongoDB also supports encryption at rest.  
With the Enterprise solution, we can encrypt all the storage files.  
Individual fields inside collections can also be encrypted or hashed.


## MongoDB deployment

#### Replica set

By default, we only run a single MongoDB node that receives all requests.  
We can use multiple nodes instead, that form a replica set.   
One node is the primary node in charge of all the WRITE operations, that it propagates asynchronously to all secondary nodes.  
Each node in the replica set contains a full copy of the primary node.  
The READ operations can be processed by the primary node or by any secondary node.  
If the primary node is down, a new primary node is elected among the secondary nodes.  
This improves both performance and availability, allowing one node to go down without much impact on the MongoDB database.

#### Sharding

MongoDB allows sharding, which is the split of the MongoDB database across multiple machines.  
It is different from a replica set, where all nodes are replicas of a same primary node.  
With sharding, the data is not duplicated, it is distributed over multiple shards.  
Each incoming query needs to be ran on the shard(s) containing the requested data.

MongoDB uses the `mongos` router to receiving incoming queries and dispatch them to the target shards.

When using sharding, all documents have a shard key, that decides in what shard it will be added.  
The shard key should be chosen to be evenly distributed across shards.  
Each incoming query can specify a shard key, in that case only the target shard will receive the query.  
If no shard key is specified, all shards will receive the query.

#### Cloud Deployment with MongoDB Atlas

The manual deployment and management of MongoDB to a production server is a tedious task.  
We need to manage shards, replica sets, encryption at rest and in transit, backups, software updates...  
MongoDB offers a SaaS solution to manage MongoDB databases on the cloud, called MongoDB Atlas.

MongoDB Atlas offers several tiers (Serverless, Dedicated and Shared) with different pricing.  
It is using AWS, Google Cloud Platform or Microsoft Azure in the background.  
It has a free tiers for Shared MongoDB server with up to 512 Mb of storage.

From the MongoDB Atlas website, register and create a free tiers account.  
It lets us create a configurable cluster of nodes that will be deployed by MongoDB Atlas in the cloud.  
By default, the deployed cluster has a replica set of 3 nodes.  
We have access to a dashboard where we can monitor our databases in real time, create collections and documents, setup the security of the database...

We can specify the whitelist of IP addresses that are allowed to query the MongoDB server.  
That should be limited to our local development adress and our client application IP address.

With the paid version of Atlas, we can create backups of the database to prevent data loss.

On the cluster page, we have a button to connect to the MongoDB server with the MongoDB Shell, with a driver, with Compass or from VS Code.  
For example if we choose "Connect from the MongoDB Shell", it provides the command line to start a client connecting to that cluster in the cloud. 


### MongoDB Stitch

MongoDB Stitch is a serverless platform for building applications.  
It is now part of the more recent MongoDB Realm platform.  
It provides a backend solution for mobile apps, web apps or desktop apps (similar to Firebase).  
It can replace a Node.js REST API for example, and be called directly from a frontend (React, Angular...).

MongoDB Stitch is integrated with MongoDB Atlas for its database solution.  
It also offers an Authentication solution for users of our app.  
Stitch lets the frontend users directly access the DB, and it allows granular configuration of what users can do.

Stitch supports functions (similar to AWS Lambda functions) that can be executed in the cloud in response to some events (triggers).

Stitch has no storage solution, but it can integrate with AWS S3 for storage.

These services are available from the MongoDB Atlas console, under the `App Services` tab.