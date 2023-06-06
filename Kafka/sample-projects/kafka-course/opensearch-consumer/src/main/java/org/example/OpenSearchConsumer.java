package org.example;

import com.google.gson.JsonParser;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.DefaultConnectionKeepAliveStrategy;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.errors.WakeupException;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.RestClient;
import org.opensearch.client.RestHighLevelClient;
import org.opensearch.client.indices.CreateIndexRequest;
import org.opensearch.client.indices.GetIndexRequest;
import org.opensearch.common.xcontent.XContentType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Collections;
import java.util.Properties;

/**
 * Consumer that reads data from Kafka and sends it to an OpenSearch server.
 * OpenSearch is an open-source fork of ElasticSearch.
 * The OpenSearch server can be on a local docker container or on the cloud.
 *
 * In this project we deploy it on Bonsai, an OpensSearch SaaS on the cloud.
 * The free account offers a single cluster.
 * From the Bonsai cluster console, we can send some REST queries :
 *   GET /                      info about the cluster
 *   PUT /my-index-1            create an index
 *   DELETE /my-index-1         delete an index
 *   PUT /my-index-1/_doc/1     create a document in the index
 *   GET /my-index-1/_doc/1     get a document saved in the index
 *   DELETE /my-index-1/_doc/1  delete a document from the index
 */
public class OpenSearchConsumer {

    public static Logger log = LoggerFactory.getLogger(OpenSearchConsumer.class);
    public static final String WIKIMEDIA_INDEX_NAME = "wikimedia";

    // the topic name must match the topic used by the Wikimedia stream producer
    public static final String WIKIMEDIA_TOPIC_NAME = "wikimedia.recentchange";

    // URL to reach the OpenSearch REST API
    // when using Bonsai, it can be found under the "Credentials" section
    public static final String OPEN_SEARCH_URL = "https://<user>:<pwd>@<host>.<region>.bonsaisearch.net:443";


    // method to get an OpenSearch client (support with and without security)
    public static RestHighLevelClient createOpenSearchClient() {
        RestHighLevelClient restHighLevelClient;
        URI connectionUri = URI.create(OPEN_SEARCH_URL);
        String userInfo = connectionUri.getUserInfo();
        if (userInfo == null) {
            log.info("Initializing OpenSearch client without security");
            restHighLevelClient = new RestHighLevelClient(RestClient.builder(
                    new HttpHost(connectionUri.getHost(), connectionUri.getPort(), connectionUri.getScheme())
            ));
        } else {
            log.info("Initializing OpenSearch client with security");
            String[] auth = userInfo.split(":");
            CredentialsProvider cp = new BasicCredentialsProvider();
            cp.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(auth[0], auth[1]));
            restHighLevelClient = new RestHighLevelClient(RestClient.builder(
                    new HttpHost(connectionUri.getHost(), connectionUri.getPort(), connectionUri.getScheme())
            ).setHttpClientConfigCallback(
                    httpAsyncClientBuilder -> httpAsyncClientBuilder.setDefaultCredentialsProvider(cp)
                            .setKeepAliveStrategy(new DefaultConnectionKeepAliveStrategy())
            ));
        }
        return restHighLevelClient;
    }


    private static KafkaConsumer<String, String> createKafkaConsumer() {
        Properties properties = new Properties();
        // set connection properties
        properties.setProperty(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        // set consumer properties
        properties.setProperty(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        properties.setProperty(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class.getName());
        properties.setProperty(ConsumerConfig.GROUP_ID_CONFIG, "my-opensearch-group");
        properties.setProperty(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");  // none / earliest / latest

        return new KafkaConsumer<>(properties);
    }


    public static String extractId(String jsonRecord) {
        // use the Gson Google library to parse the JSON string
        return JsonParser.parseString(jsonRecord).getAsJsonObject()
                .get("meta").getAsJsonObject()
                .get("id").getAsString();
    }


    public static void main(String[] args) throws IOException {

        // create the OpenSearch client
        RestHighLevelClient openSearchClient = createOpenSearchClient();

        // create the Kafka consumer
        KafkaConsumer<String, String> kafkaConsumer = createKafkaConsumer();

        // get a reference to the main thread and add a shutdown hook
        final Thread mainThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                log.info("Shutdown requested");
                // wakeup the consumer so it will throw a WakeupException the next time it tries to poll
                // our code can catch this WakeupException
                kafkaConsumer.wakeup();

                try {
                    // join the main thread to wait for proper shutdown
                    mainThread.join();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        try {
            // create the OpenSearch index if it does not exist yet
            try {
                boolean exists = openSearchClient.indices().exists(new GetIndexRequest("wikimedia"), RequestOptions.DEFAULT);
                if (!exists) {
                    log.info("Creating " + WIKIMEDIA_INDEX_NAME + " index...");
                    CreateIndexRequest createIndexRequest = new CreateIndexRequest(WIKIMEDIA_INDEX_NAME);
                    openSearchClient.indices().create(createIndexRequest, RequestOptions.DEFAULT);
                    log.info("The " + WIKIMEDIA_INDEX_NAME + " index was created successfully.");
                } else {
                    log.info("The " + WIKIMEDIA_INDEX_NAME + " index already exists.");
                }
            } catch (Exception e) {
                log.warn("Caught an exception...");
            }

            // subscribe to the wikimedia topic
            kafkaConsumer.subscribe(Collections.singleton(WIKIMEDIA_TOPIC_NAME));

            // infinite loop reading the wikimedia changes and storing them in OpenSearch
            while (true) {
                // read from Wikimedia stream
                ConsumerRecords<String, String> records = kafkaConsumer.poll(Duration.ofMillis(2000));
                log.info("Received " + records.count() + " records.");

                // batch the records into a single bulk request
                BulkRequest bulkRequest = new BulkRequest();
                for (ConsumerRecord<String, String> record : records) {
                    log.info("Retrieved record from Kafka : " + record.value());
                    // create a request to insert the record in OpenSearch
                    // we use an ID from the record so the operation is idempotent
                    IndexRequest indexRequest = new IndexRequest(WIKIMEDIA_INDEX_NAME);
                    indexRequest.source(record.value(), XContentType.JSON);
                    indexRequest.id(extractId(record.value()));
                    // instead of calling opensearchClient.index() for each record, we bulk then together
                    // and send a single bulk request per batch
                    bulkRequest.add(indexRequest);
                }

                // send all polled records in a single OpenSearch request
                if (bulkRequest.numberOfActions() > 0) {
                    BulkResponse bulkResponse = openSearchClient.bulk(bulkRequest, RequestOptions.DEFAULT);
                    log.info("Inserted " + bulkResponse.getItems().length + " records in OpenSearch");
                }

                // by default, the consumer will auto-commit the polled documents when calling poll() if the
                // commit interval has elapsed (auto.commit.interval.ms)
                // we can choose to commit manually instead by setting enable.auto.commit to false
                // and calling consumer.commitSync()
            }
        } catch (WakeupException e) {
            log.info("Consumer shutting down...");
        } catch (Exception e) {
            log.error("An unexpected error occurred while polling messages", e);
        } finally {
            // close resources
            openSearchClient.close();
            kafkaConsumer.close();
        }
    }
}
