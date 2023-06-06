package org.example;

import com.launchdarkly.eventsource.EventHandler;
import com.launchdarkly.eventsource.EventSource;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * Process that receives a stream of messages from Wikimedia recent changes
 * and insert these changes as Kafka messages
 *
 * It uses the OkHttp and the OkHttp-eventsource libraries to receive the
 * stream from Wikimedia recent changes.
 */


public class WikimediaProducerDemo {

    private static final Logger log = LoggerFactory.getLogger(WikimediaProducerDemo.class.getSimpleName());

    public static void main(String[] args) throws InterruptedException {

        log.info("Starting the producer...");

        Properties properties = new Properties();
        // set connection properties
        properties.setProperty(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        // set producer properties
        properties.setProperty(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        properties.setProperty(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());

        // create the producer
        KafkaProducer<String, String> producer = new KafkaProducer<>(properties);

        // create an event source that sends a Kafka message on stream reception
        String topic = "wikimedia.recentchange";
        String wikimediaUrl = "https://stream.wikimedia.org/v2/stream/recentchange";
        EventHandler eventHandler = new WikimediaChangeHandler(producer, topic);
        EventSource.Builder builder = new EventSource.Builder(eventHandler, URI.create(wikimediaUrl));
        EventSource eventSource = builder.build();

        // start the producer in another thread
        eventSource.start();

        // prevent the main thread to stop
        TimeUnit.MINUTES.sleep(1);

        log.info("Stopping the producer...");
    }
}
