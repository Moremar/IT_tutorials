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
        String database = "athena-db-name";
        String table = "athena-table-name";
        String bucket = "my-athena-output-bucket";
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