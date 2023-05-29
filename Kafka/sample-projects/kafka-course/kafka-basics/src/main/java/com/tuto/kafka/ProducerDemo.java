package com.tuto.kafka;

import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
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
        properties.setProperty("bootstrap.servers", "localhost:9092");
        // set producer properties
        properties.setProperty("key.serializer", StringSerializer.class.getName());
        properties.setProperty("value.serializer", StringSerializer.class.getName());

        // create the producer
        KafkaProducer<String, String> producer = new KafkaProducer<>(properties);

        // create a producer record
        ProducerRecord<String, String> record = new ProducerRecord<>("demo_topic", "Hello World");

        // send the record to Kafka
        producer.send(record);

        // force the producer to send its data and block until completion
        producer.flush();
        producer.close();

        log.info("Stopping the producer...");
    }
}
