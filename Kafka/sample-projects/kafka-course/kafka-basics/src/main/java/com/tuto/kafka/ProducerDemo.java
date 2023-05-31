package com.tuto.kafka;

import org.apache.kafka.clients.producer.*;
import org.apache.kafka.common.serialization.StringSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

public class ProducerDemo {

    private static final Logger log = LoggerFactory.getLogger(ProducerDemo.class.getSimpleName());
    public static void main(String[] args) {

        log.info("Starting the producer...");

        Properties properties = new Properties();
        // set connection properties
        properties.setProperty(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, "localhost:9092");
        // set producer properties
        properties.setProperty(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        properties.setProperty(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());

        // create the producer
        KafkaProducer<String, String> producer = new KafkaProducer<>(properties);

        // create a producer record with no key
        String topic = "demo_topic";
        ProducerRecord<String, String> record1 = new ProducerRecord<>(topic, "Hello 1");

        // send the record with no key to Kafka
        // provide an optional callback executed on message send completion
        producer.send(record1, (metadata, e) -> {
            if (e == null) {
                // record successfully sent
                log.info("Sent record 1 :"
                        + " topic = " + metadata.topic() + " partition = " + metadata.partition()
                        + " offset = " + metadata.offset() + " timestamp = " + metadata.timestamp()
                );
            } else {
                log.error("An error occurred while sending the record", e);
            }
        });

        // create a producer record with a key
        ProducerRecord<String, String> record2 = new ProducerRecord<>(topic, "key1","Hello 2");

        // send the record to Kafka
        // provide an optional callback executed on message send completion
        producer.send(record2, (metadata, e) -> {
            if (e == null) {
                // record successfully sent
                log.info("Sent record 2 :"
                        + " topic = " + metadata.topic() + " partition = " + metadata.partition()
                        + " offset = " + metadata.offset() + " timestamp = " + metadata.timestamp()
                );
            } else {
                log.error("An error occurred while sending the record", e);
            }
        });


        // force the producer to send its data and block until completion
        producer.flush();
        producer.close();

        log.info("Stopping the producer...");
    }
}
