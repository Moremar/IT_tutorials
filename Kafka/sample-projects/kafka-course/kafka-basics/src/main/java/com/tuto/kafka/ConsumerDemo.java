package com.tuto.kafka;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.ConsumerRecords;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.errors.WakeupException;
import org.apache.kafka.common.protocol.types.Field;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Arrays;
import java.util.Properties;

public class ConsumerDemo {
    private static final Logger log = LoggerFactory.getLogger(ConsumerDemo.class.getSimpleName());
    public static void main(String[] args) {

        log.info("Starting the consumer...");

        Properties properties = new Properties();
        // set connection properties
        properties.setProperty("bootstrap.servers", "localhost:9092");
        // set consumer properties
        properties.setProperty("key.deserializer", StringDeserializer.class.getName());
        properties.setProperty("value.deserializer", StringDeserializer.class.getName());
        properties.setProperty("group.id", "my-java-group");
        properties.setProperty("auto.offset.reset", "earliest");  // none / earliest / latest

        // create consumer
        KafkaConsumer<String, String> consumer = new KafkaConsumer<>(properties);

        // get a reference to the main thread and add a shutdown hook
        final Thread mainThread = Thread.currentThread();
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                log.info("Shutdown requested");
                // wakeup the consumer so it will throw a WakeupException the next time it tries to poll
                // our code can catch this WakeupException
                consumer.wakeup();

                try {
                    // join the main thread to wait for proper shutdown
                    mainThread.join();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        });

        // subscribe to a topic
        String topic = "demo_topic";
        consumer.subscribe(Arrays.asList(topic));

        // poll for data
        // inside a try/catch to ensure we catch the WakeupException on shutdown
        try {
            while (true) {
                log.info("Polling the topic...");
                ConsumerRecords<String, String> records = consumer.poll(Duration.ofMillis(1000));

                for (ConsumerRecord<String, String> record : records) {
                    log.info("key = " + record.key() + " value = " + record.value()
                            + " partition = " + record.partition() + " offset = " + record.offset());
                }
            }
        } catch (WakeupException e) {
            log.info("Consumer shutting down...");
        } catch (Exception e) {
            log.error("An unexpected error occured while polling messages", e);
        } finally {
            // commit the offset and close the consumer
            consumer.close();
            log.info("Consumer shutdown successful");
        }

//        log.info("Stopping the consumer...");
    }
}
