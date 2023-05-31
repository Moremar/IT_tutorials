package org.example;

import com.launchdarkly.eventsource.EventHandler;
import com.launchdarkly.eventsource.MessageEvent;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WikimediaChangeHandler implements EventHandler {
    private static final Logger log = LoggerFactory.getLogger(WikimediaChangeHandler.class.getSimpleName());

    /*
     * Member variables
     */
    private final KafkaProducer<String, String> producer;
    private final String topic;


    public WikimediaChangeHandler(KafkaProducer<String, String> producer, String topic) {
        this.producer = producer;
        this.topic = topic;
    }

    @Override
    public void onOpen() {
        log.info("Calling WikimediaChangeHandler.onOpen()");
    }

    @Override
    public void onClosed() {
        log.info("Calling WikimediaChangeHandler.onClosed()");
        this.producer.close();
    }

    @Override
    public void onMessage(String event, MessageEvent messageEvent) {
        log.info("Sending " + messageEvent.getData());
        // async send message to Kafka
        this.producer.send(new ProducerRecord<>(this.topic, messageEvent.getData()));
    }

    @Override
    public void onComment(String comment) {
        log.info("Calling WikimediaChangeHandler.onComment()");
    }

    @Override
    public void onError(Throwable t) {
        log.error("Calling WikimediaChangeHandler.onError()", t);
    }
}
