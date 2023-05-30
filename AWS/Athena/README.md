# AWS Athena Tutorial


## Athena Overview

Athena is a serverless interactive query platform to query data stored on S3.

Athena uses standard SQL to query the data.  
Athena supports a variety of formats : CSV, JSON, Avro, Parquet, ORC...  
Athena can be used from the AWS Console, from the AWS CLI, from the programming APIs or via a JDBC connection.

It integrates with AWS Glue to retrieve the schema of data in S3.  
It also integrates with QuickSight for Data Visualization (pie charts).

Athena is popular for Big Data on large data sets, as a replacement of a Hadoop cluster.

Athena stores its results in an output folder in S3.

## Setup

### Authentication

To call Athena from inside AWS, we need a role with Athena permission.  
If we run a Lambda function using the Athena client, it will also need such a role.

To call Athena from outside AWS, we need an AWS access key and a secret key.  
It can be generated in the AWS Manamgement Console from `IAM > Users > Security Credentials`


### Sample data

To practise using Athena, we need sample data in S3.  
We can for example generate dummy data in [Mockaroo](https://www.mockaroo.com/) and upload it to a sample S3 bucket.


## Tables Preparation with AWS Glue Crawlers

### Glue Overview

Glue is a serverless fully-managed ETL service (Extract / Transform / Load).  
It is used to lean data, enrich it and move it from a data store to another.  

The main Glue components are :
- Glue Data Catalog : central metadata repository
- Glue Crawlers : scan data and populate the data catalog
- ETL Engine : generate Python/Scala code for the data enrichment process
- Glue Triggers : scheduler for crawlers jobs
- Glue Workflow : orchestrate steps of the ETL jobs

### Glue Crawlers

A Glue Crawler can scan data from a data source and create associated metadata in a table of the Glue Data Catalog.  
This table can be used by some services (Athena, ETL jobs, Redshift...) to know the schema of the data.

Glue Crawlers can crawl natively from S3 and DynamoDB.  
Using a JDBC client, they can crawl all relational DBs (MySQL, PostreSQL, Oracle...).  
With the MongoDB client, they can crawl MongoDB and DocumentDB.

Glue uses classifiers to determine the type of files of the input data source.  
It has built-in classifiers for popular file types (JSON, CSV, Parquet, AVRO...) and can support custom classifiers.

Glue also supports compressed files, it will decompress them before applying the classifiers.

When creating a crawler in AWS, we specify its source, its output, its schedule, its IAM role.  
Once created, we can run the crawler, and it will create a table under Glue > Databases > Tables.


## Query in Athena

In the Athena query screen, we can see the tables from AWS Glue in the Data panel.

We can for example click on a table and select "Preview Table" to generate the corresponding SQL query.  
Before running the query, we need to specify the output S3 folder for the Athena results.  
Once done, we can click the "Run" button to perform the query.  
The results appear in Athena, and are saved in the S3 output folder.

Queries used frequently can be added to the Saved Queries sections.

It is possible to use Athena without storing the table in Glue.  
In that case, we can create a table directly from Athena, but it is more tedious as it requires to input every column and its type one by one.


## Athena Partitioning

Athena can define partitions on tables, to keep related data together and reduce the amount of data scanned.

Queries with a `WHERE` clause on partitioned fields will only scan the data of the relevant partitions.

This requires the data to be organized in S3 according to these partitions.  
For example, we could have a data set split by region, then by year, then by month.  
Partitions would allow to run queries for a given region and year without scanning files for other regions and years.

There are 2 possible naming conventions for S3 folders using partitions :
- each partition folder has the form `<field_name>=<field_value>`, for example `region=ASIA` or `year=2023`
- each partition folder has the form `<field_value>`, for example `ASIA` or `2023`

To create a table with partitions in Athena, we can add to the `CREATE TABLE` DLL query a `PARTITIONED BY` block like :
```commandline
PARTITIONED BY ( `year` string, `month` string )
```

Before Athena can query data on a partitioned table, it needs to load the partitions.  
This can be done by right-clicking on the table and choosing "Load Partitions".  
It runs the below Athena metadata scanner command :
```sql
MSCK REPAIR TABLE table_name;
```
This adds partitions to the metadata, and then the table can be queried.


## Lambda Automation


### Load partitions with Lambda

In a production environment, we cannot manually load the partitions everytime a file is added to S3 in a new partition folder.  
Instead, we can automate it with a Lambda function triggered after S3 insertion in the source bucket.  

We can create a Lambda function from the blueprint called `s3-get-object-python`.  
The Lambda function needs permission with S3, Cloudwatch and Athena.    
It should trigger on every object creation.

The Lambda function must be on the same region as the S3 bucket, and its body can be :

```python
s3 = boto3.client('s3')
athena = boto3.client('athena')
athena_db = 'my_athena_database'

def lambda_handler(event, context):
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.parse.unquote_plus(event['Records'][0]['s3']['object']['key'], encoding='utf-8')
    
    # the athena table name is the top folder name of the S3 path
    position = key.index('/')
    table_name = key[:int(position)]
    
    # SQL query to load partitions
    sql = 'MSCK REPAIR TABLE ' + athena_db + '.' + table_name
    query_context = { 'Database': athena_db }
    result_config = { 'OutputLocation': 's3://' + bucket + '/athena_output/' }

    # send the load partitions query to Athena
    try:
        athena.start_query_execution(
            QueryString = sql,
            QueryExecutionContext = query_context,
            ResultConfiguration = result_config)
    except Exception as e:
        print(e)
        print(f'Failed to get object {key} from bucket {bucket}')
        raise e
```

We can check in Athena with `show partitions my_table_name` that a partition does not exist.  
Then manually create the folder for the partition in the S3 bucket and add a file.    
Ensure that the Lambda function gets triggered, and that the partition now appears with the above query.


### Athena query with Lambda

A Lambda function can also be created to run a query on Athena.  
It needs a role with permission to perform queries on Athena, write on S3 and in CloudWatch.

In a Python 3 Lambda function, we can call the `start_query_execution()` method to execute an SQL query in Athena.  
It starts the query in QUEUED state, and the query will be executed and move to RUNNING, then SUCCEEDED or FAILED.  
Once the results are ready, they are retrieved with `get_query_results()` :

```python
import boto3
import time

athena = boto3.client('athena')

athena_db = 'my-athena-db'
table_name = 'my_table'
sql = 'SELECT * FROM "' + athena_db + '"."' + table_name + '" limit 10'
bucket = 'my-bucket-for-athena'


def lambda_handler(event, context):
    
    # start the Athena query
    # the query goes to QUEUED state
    response = athena.start_query_execution(
        QueryString = sql,
        QueryExecutionContext = { 'Database': athena_db },
        ResultConfiguration = { 'OutputLocation' : 's3://' + bucket + '/athena_output/' } )

    query_execution_id = response['QueryExecutionId']

    # wait for the query execution to complete
    status = 'QUEUED'
    while status not in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
        time.sleep(1)
        query_execution = athena.get_query_execution(QueryExecutionId = query_execution_id)
        status = query_execution['QueryExecution']['Status']['State']
        print('Athena query is ' + status)
    
    # access the results of the query
    results = athena.get_query_results(QueryExecutionId = query_execution_id)

    # loop over the rows to performa any action we need
    for row in results['ResultSet']['Rows']:
        print(row)
    
    return {
        'statusCode': 200,
        'body': 'Results retrieved from Athena!'
    }
```

### Athena query with JDBC in Java

Create a new Maven Project and add `aws-java-sdk-athena` to the Maven `<dependencies>` block in `pom.xml`.  

The structure of the program is similar to the above Python one.  
First we create an Athena client of type `AmazonAthena`.  
We create a query of type `StartQueryExecutionRequest` and send it to Athena with `athenaClient.getQueryExecution()`.  
To monitor the results, we create a results request of type `GetQueryResultsRequest` and call `athenaClient.getQueryExecution()`.  
When the state of the result is SUCCEEDED, we can iterate on the results from the Java code.

AWS credentials are directly entered in code in the below example.  
For a real production program, these should come from environment variables or from `.aws/credentials`.

```java
package org.example;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.athena.AmazonAthena;
import com.amazonaws.services.athena.AmazonAthenaClientBuilder;
import com.amazonaws.services.athena.model.*;


class AthenaExample {
    public static void main(String[] args) {

        System.out.println("Starting the Athena query");

        // Set up the AWS access key ID and secret access key
        String accessKey = "xxx";
        String secretKey = "xxxxx";
        BasicAWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);

        // Set up the Athena client
        String region = "ap-northeast-1";
        AmazonAthena athenaClient = AmazonAthenaClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .withRegion(region)
                .build();

        // Define the Athena query execution parameters
        String database = "mydatabase";
        String table = "mytable";
        String bucket = "mybucket";
        String query = "SELECT * FROM " + table + " LIMIT 10";

        // Create the StartQueryExecutionRequest
        StartQueryExecutionRequest startQueryRequest = new StartQueryExecutionRequest()
                .withQueryString(query)
                .withQueryExecutionContext(new QueryExecutionContext().withDatabase(database))
                .withResultConfiguration(new ResultConfiguration().withOutputLocation("s3://" + bucket + "/athena_output/"));

        // Start the Athena query execution
        StartQueryExecutionResult startQueryResult = athenaClient.startQueryExecution(startQueryRequest);
        String queryExecutionId = startQueryResult.getQueryExecutionId();

        // Check the status of the query execution
        GetQueryExecutionRequest getQueryExecutionRequest = new GetQueryExecutionRequest()
                .withQueryExecutionId(queryExecutionId);

        GetQueryExecutionResult getQueryExecutionResult;
        String state;
        do {
            getQueryExecutionResult = athenaClient.getQueryExecution(getQueryExecutionRequest);
            state = getQueryExecutionResult.getQueryExecution().getStatus().getState().toString();
            System.out.println("Query execution state: " + state);

            try {
                Thread.sleep(1000); // Wait for 1 second before checking again
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        } while (state.equals(QueryExecutionState.SUCCEEDED.toString()));

        // Get the query results
        GetQueryResultsRequest getQueryResultsRequest = new GetQueryResultsRequest()
                .withQueryExecutionId(queryExecutionId);

        GetQueryResultsResult getQueryResultsResult = athenaClient.getQueryResults(getQueryResultsRequest);
        for (Row row : getQueryResultsResult.getResultSet().getRows()) {
            for (Datum datum : row.getData()) {
                System.out.print(datum.getVarCharValue() + "\t");
            }
            System.out.println();
        }

        // Cleanup resources (optional)
        athenaClient.stopQueryExecution(new StopQueryExecutionRequest().withQueryExecutionId(queryExecutionId));
    }
}
```