# Kafka Tutorial


## Introduction

Kafka is a distributed streaming platform to send data from some message producers to some message consumers.  
It was created by LinkedIn and is now open-source and used by many major companies (AirBnB, Netflix, Twitter, ...).

Kafka is distributed across multiple brokers (servers in a cluster).  
It is fault-tolerant by replicating data across brokers.  
It is horizontally scalable by adding or removing brokers to the cluster.  
It is quasi real-time with high performance at the ms level.  
It can scale to millions of messages per second.

Kafka can be used as a messaging system, for activity tracking, metric gathering, application logs, stream processing, service decoupling ...  
It also integrates with Big Data technologies like Hadoop.


## Kafka Architecture


### Topics

A topic is a stream of data identified by a unique name.  
A cluster can have any number of topics.  
A message is always sent to a given topic, and it supports any type of data (text, JSON, Protobuf, binary).  
A sequence of messages in a topic is called a "data stream".  

Once a topic is being used by some consumers, it must never change the type of its key or value, or it would break consumers.  
In that case, a new topic should be created instead, and consumers should be adjusted to use this new topic.

Each topic has a replication factor, it is the number of different brokers storing each partition of this topic.    
The replication factor must be higher than 1 to ensure fault tolerance in case of a broker failure.   

Only one broker can be the leader for a given partition of a topic.  
Producers only send messages to the leader broker for a given partition.  
Other brokers storing this partition are only replicas in case the leader goes down.  
After each message insertion in a leader broker, Kafka will replicate this message to every replica.  

By default, consumers request messages only from the leader broker for each partition.  
Since Kafka 2.4, consumers can read from the closest replica (instead of the leader) to improve latency.


### Partitions

A partition is a division of a topic, a topic can have any number of partitions.  
The partition to which a message belongs is determined by a hash of its message key.  
2 messages sent to a topic with the same key will always be part of the same partition.  
Kafka messages are guaranteed to be ordered within a partition, but not across partitions !  
A message only belongs to a single partition of a topic.  

Once a message is written to a partition, it can never be modified or deleted.  
Messages in Kafka are kept only for a limited time, specified with `offset.retention.minutes` (7 days by default).  
After that time, messages are deleted permanently from Kafka.


### Segments

Internally, partitions are made of segments that are files containing a successive ranges of messages.  
A segment has a min and a max offset, and only 1 segment can be active at a time (the one currently being written to).

If the cleanup policy is set to `log.cleanup.policy=delete`, Kafka deletes the oldest segments, either when they are older than the retention time, or when the partition takes more than the retention bytes limit.  

Instead of deleting old messages, we can set up compaction with `log.cleanup.policy=compact` if we only need the latest value for a given key.  
In that case, when a segment is closed, Kafka will rewrite previous segments to only include the latest message for each key.


### Message Offsets

The offset of a message is its position within its partition.  
Offsets are not re-used even after older messages get deleted.  
Offsets are always increasing within a partition.


### Kafka Producers

A producer is a process writing some messages to a topic.  
The producer decides what partition the message belongs to by hashing its message key.  

If no message key is provided, the producer will choose a partition using its partitioner.  
The partitioner could choose to send messages without a key following a round-robin strategy.  
For performance improvement, providers can use a sticky partitioner, that sends messages together to a same partition if sent close enough from each other.


A producer can choose to receive a ACK of each message sent to kafka :
- `acks=0` : the producer does not wait for any ack (possible data loss)
- `acks=1` : the producer waits for the ack from the leader broker (rare data loss)
- `acks=all` : the producer waits for the ack from the leader and all replicas (no data loss)

Producers retry to send messages when they get an exception, until their timeout is reached (`delivery.timeout.ms` property defaulting to 2min).

Kafka supports idempotent producers, when we use them Kafka recognizes a duplicate if it receives one and does not commit it again.  
Idempotent producers are the default from Kafka 3.0.

### Kafka Messages

A message is a single piece of data sent to a topic by a producer.  
By default, a Kafka message cannot exceed 1MB.

A message generated by a producer is made of :
- a message key (to decide the partition)
- a message value
- a compression type (none, gzip, ...)
- K/V headers (optional)
- a partition and an offset
- a timestamp

Messages must be serialized (using Kafka serializers) before sending them to a producer.  
Messages must be deserialized after retrieving them with a consumer.

A message key should be set to ensure partial ordering between related messages.  
The key can be of any type (text, number, binary...).  
For example, if events are sent every second to identify the position of a float of drones, we can use the drone ID as a key,
so the successive positions of a given drone are ordered in Kafka.


### Kafka Consumers

A consumer is a process reading the messages from a topic.  
Consumers request messages to the Kafka brokers (brokers do not push messages to consumers).  
Messages are read in order from lowest to highest offsets within each partition.  
Consumers deserialize the binary data they receive from the brokers.  
If the key is an integer and the message value is a string, we would use an IntegerDeserializer and a StringDeserializer. 

Consumers re-balance their partition allocation at startup of shutdown of a consumer, driven by the `partition.assignment.strategy` property :
- **eager rebalance** : stop all consumers and rejoin the group, for a short time all consumers are down, and a consumer may receive a partition different from what it had before.
- **cooperative rebalance** : reassign only a subset of partitions, Kafka figures out what partitions need to be assigned to a new consumer, and only interrupts the read from these partitions, no interruption for partitions that are not changing consumer.

A Kafka consumer commits its offsets when we call `poll()` and the `auto.commit.interval.ms` has elapsed.  
It is possible to change this behavior by setting `enable.auto.commit` to false and committing manually. 

Kafka consumers send a heartbeat regularly to the consumer regulator (a broker of the cluster).  
The heartbeat interval is set with `heartbeat.interval.ms` (3sec by default).  
The consumer is also considered dead if the time between 2 polls exceeds `max.poll.interval.ms` (5min by default).


### Kafka Consumer Groups

A consumer group is a group of consumers reading from exclusive partitions of a given topic.  
This provides horizontal scalability to the consumer tasks, allowing the processing of messages in a topic to be performed in parallel by multiple consumers.  
If there are more consumers in a group than partitions in the topic, some consumers of the group will be idle.  

Every message in the topic is read by a single consumer of the consumer group.  
Several consumer groups can read from the same topic (they are just independent groups).  
A consumer group is identified by a group ID.


### Consumer Offsets

The consumer offsets are the offsets up to which a consumer has been reading messages in each partition of a topic.  
They are stored in an internal topic called `__consumer_offsets`.  
When the consumer restarts, it will start processing messages for each partition from these consumer offsets.  
Each consumer regularly updates its consumer offset for each partition it processes.

There are 3 strategies to update this consumer offset :
- at least once (default) : guarantees that all messages are processed at least once, the consumer offset is updated after successful processing of each message.
- at most once :  guarantees that all messages are processed not more than once, the consumer offset is updated as soon as a message iss received.
- exactly once : use transactional API, only done for Kaftka to Kafka worflow.

The most common way to handle it is to use the "at least once" strategy and have an idempotent behavior in case a message is processed twice.


### Kafka Brokers and Cluster

A cluster is a group of Kafka brokers (servers).  
Each broker is identified by an ID and contains some partitions of the topics.  
A cluster can have any number of brokers (over 100 for big clusters).  

In recent Kafka versions, each broker can be used as a "bootstrap broker".  
It knows about the entire cluster and is an entry point to any Kafka query on the cluster.


### Zookeeper and Kafka Raft

Zookeeper is a dedicated software for the management of the Kafka cluster :  
- it helps in the leader election for each partition
- it sends messages across the cluster on changes (new or deleted topic, broker dies or starts...)

It used to be a mandatory element to run a Kafka cluster before Kafka 3.  
Kafka plans to replace Zoopeeper by Kafka Raft (or Kraft).  
Since Kafka 3, Kraft can replace Zookeeper, and is production-ready since Kafka 3.3.1 (2022).  
From Kafka 4, there will be no more support for Zookeeper (not released yet as of 2023).

Zookeeper shows some scaling issues for big cluster with more than 100,000 partitions.  
Without Zookeeper, Kafka can handle millions of partitions.  
Getting rid of Zookeeper also makes the Kafka configuration much easier to monitor and support.  
With Kraft, there is no longer a software managing the cluster.  
Instead, each broker is able to act as an entry point for any operation on the cluster. 


### Kafka Connect

Many applications import data from common sources to Kafka : relational DB, MongoDB, Twitter, Salesforce, SQS...  
Many applications send data from Kafka to common sinks : S3, ElasticSearch, HDFS, DynamoDB, Splunk...

Kafka Connect provides an easy and well-tested API to perform this import of data from an external source to Kafka, or from Kafka to an external sink.  

Kafka Connectors are not part of the Kafka installation, but they can be downloaded online.  
Most are free and developped by Confluent, the creators of Kafka offering a commercial platform to deploy Kafka.


### Kafka Streams

Kafka Streams is an easy data processing and transformation library in Kafka.  
It is used to automate the data transformation from one or more Kafka topic to another Kafka topic.  

A Kafka Stream can be written in Java.  
It reads messages from some Kafka topics, apply some logic on these messages and post new messages to one or more topics.


## Schema Registry

When no schema registry is in use, producers generate a message, serialize it and send it as binary to Kafka.  
Consumers fetch the binary message and deserialize it.  
In case the input data format or structure changes, the consumer would break.

We could have each broker checking received messages, but that would break the efficiency of Kafka, that relies on only receiving and sending bytes.

The schema registry is an external process that both producers and consumers interact with.  
Producers validate their messages against the schema registry before sending them to Kafka.  
Consumers receive messages and get the corresponding schema from the schema registry.

The schema registry supports Avro, Protobuf and JSON Schema types.  
It requires to update the producer and consumer code to communicate with the schema registry.

A schema in the schema registry can evolve and have newer versions.  
The schema defines a compatibility strategy, for example BACKWARD to guarantee that later versions are backward-compatible.


## Message Compression

Producers usually send text-based messages (like JSON) and can compress the batches with the `compression.type` (none / gzip / lz4 / snappy...)

The compression type can also be specified with the `compression.type` property in the broker.  
When set to `producer`, then it takes batches already compressed by producers and stores them as-is.  
When set to the same compression type as the producer, it also stores compressed messages as-is.  
When set to a different compression type (for ex `gzip` in producer and `lz4` on broker), it decompresses and recompresses to the broker compression format.

There is no need to specify the compression type on consumer side, it automatically detects the compression type and decompresses messages.

The `linger.ms` property specifies the time the producer can keep a message before sending it, so it can batch messages together (default to 0).  
Increasing it can improve performance by reducing the network traffic and improving compression.

The `batch.size` property can be adjusted too to send bigger batches.


## Kafka Setup

Kafka is open-source, so it is free to install on Windows, MacOS and Linux.  
The production configuration of Kafka is tedious and takes several hours.  
For development and testing, we can simply create a cluster locally with a single broker.


### Using Conduktor

[Conduktor](https://www.conduktor.io/) is a web service offering a Kafka GUI to start and manage Kafka clusters in the cloud.    
It follows a monthly payment system but has a free tiers with a single cluster.  

We can create a free account and create a playground to start a Kafka cluster.


### Locally on MacOS with a single broker

#### Option 1 : Manual Installation

Kafka requires Java JDK, which can be installed for example from [AWS Corretto](https://aws.amazon.com/corretto).  
Download the pkg file for the latest JDK and install it, then check that it worked with : `java --version`

Kafka binaries are available from the [Kafka download page](https://kafka.apache.org/downloads).  
Download the tgz archive, extract it, copy it to the desired location and add the `bin/` folder to the `PATH` env variable.

Start Zookeeper in a console with :
```commandline
zookeeper-server-start.sh <PATH_TO_KAFKA>/config/zookeeper.properties
```

Start a Kafka broker in another console with :
```commandline
kafka-server-start.sh <PATH_TO_KAFKA>/config/server.properties
```

The `dataDir` and `log.dir` properties can be modified in the Zookeeper and server properties files.


#### Option 2 : Installation with Homebrew

Alternatively, we can install the Kafka binaries with Homebrew :
```commandline
brew install kafka
```
Homebrew installs its packages under `/usr/local/opt/` and its config files under `/usr/local/etc/`.    
It automatically adds its `bin` folders to the `PATH` variable.    
Binaries installed with Homebrew are called without the `.sh` extension.

To start Zookeeper installed with Homebrew ;
```commandline
zookeeper-server-start /usr/local/etc/zookeeper/zoo.cfg
```

Start a Kafka broker in another console with :
```commandline
kafka-server-start /usr/local/etc/kafka/server.properties
```


### Locally on Windows with a single broker

Kafka can be run on Windows 10 using WSL2 (Windows Subsystem for Linux) that provides a real Ubuntu kernel inside Windows.  
It is installed in an administrator shell with :  `wsl --install`  
On completion, restart Windows, it opens a terminal installing Ubuntu.  
After entering a username and password, the Ubuntu box is started.  
We now have a Ubuntu app in the Windows Start menu.

Install Java, for example the AWS Corretto JDK :
```commandline
sudo wget -O- https://apt.corretto.aws/corretto.key | sudo apt-key add - 
sudo add-apt-repository 'deb https://apt.corretto.aws stable main'
sudo apt-get update; sudo apt-get install -y java-17-amazon-corretto-jdk
java --version
```

Install Kafka from their Download page in the Ubuntu box :
```commandline
wget https://downloads.apache.org/kafka/3.4.0/kafka_2.13-3.4.0.tgz
tar xzvf kafka_2.13-3.4.0.tgz
```

Add the `bin/` folder to the `PATH` by adding to `~/.bashrc` :
```commandline
PATH="$PATH:~/kafka_2.13-3.4.0/bin/"
```

Start Zookeeper using the default property files in the tgz archive :
```commandline
zookeeper-server-start.sh ~/kafka_2.13-3.4.0/config/zookeeper.properties
```

Start a Kafka broker using the default property files in the tgz archive :
```commandline
kafka-server-start.sh ~/kafka_2.13-3.4.0/config/server.properties
```

To make the Kafka cluster reachable from ouside Ubuntu (PowerShell, Java...) we need to adjust the config.  
First disable IPV6 :
```commandline
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
```
Then edit the `config/server.properties` Kafka configuration file to set the `listeners` property :
```commandline
listeners=PLAINTEXT://localhost:9092
```


## Kafka CLI

Since Zookeeper is getting deprecated, client commands should use the `--bootstrap-server` option instead of `--zookeeper` to use Kraft.

When using a secure cluster (for example a cluster managed on Conduktor), we should create a config file with the broker properties.  
These properties are available in Conduktor under `Kafka Cluster > Advanced properties` and look like :

###### conduktor-cluster.config
```commandline
security.protocol=SASL_SSL
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username='xxx' password='xxx.xxx.xxx';
```

All below CLI commands are using a local Kafka cluster so they only require `--bootstrap-server localhost:9092`  
To run the query for a Conduktor cluster, replace it by `--bootstrap-server cluster.playground.cdkt.io:9092 --command-config /tmp/conduktor-cluster.config`  
For example, to describe all existing topics :

```commandline
kafka-topics --describe --bootstrap-server cluster.playground.cdkt.io:9092 --command-config /tmp/conduktor-cluster.config
```

### Topic management

Topics are managed with the `kafka-topics` Kafka CLI command. 

#### Create a topic

The topic creation uses the `--create` command with the `--topic <TOPIC_NAME>` parameter.  
The number of partitions of the topic can be specified with the `--partitions <INT>` parameter.  
The replication factor can be set with `--replication-factor <INT>` and cannot be more than the number of brokers.

```commandline
kafka-topics --bootstrap-server localhost:9092 --create --topic test-topic
```

#### List existing topics

The `--list` command simply list the name of existing topics.  
To get more detailed info about each topic (leader, partitions, replicas...), use the `--describe` command instead.

```commandline
kafka-topics --bootstrap-server localhost:9092 --list
kafka-topics --bootstrap-server localhost:9092 --describe 
``` 


#### Delete a topic

The topic deletion uses the `--delete` command with the `--topic <TOPIC_NAME>` parameter.  

```commandline
kafka-topics --bootstrap-server localhost:9092 --delete --topic test-topic
```


#### Configure a topic

Topics can be configured with the `kafka-configs` binary on the `topics` type :
```commandline
kafka-configs --bootstrap-server localhost:9092 --entity-type topics --entity-name my-topic --alter --add-config min.insyn.replicas=2
```


### Kafka Producer

A console producer can be used with the `kafka-console-producer` Kafka CLI command.

To write some messages to a topic, we can use the below command.  
It opens a stream, and we can write a message per line, then Ctrl-C to stop sending messages.

```commandline
kafka-console-producer  --bootstrap-server localhost:9092 --topic test-topic
> my message 1
> my message 2
> Ctrl-C
```

We can force the producer to wait for all brokers to ack with `--producer-property acks=all`

We can specify a key for each message by adding the `--property parse.key=true` and `--property key.separator=:` arguments :

```commandline
kafka-console-producer  --bootstrap-server localhost:9092 --topic test-topic --property parse.key=true --property key.separator=:
> keyA:my message 1
> keyA:my message 2
> keyB:my message 1
> Ctrl-C
```

### Kafka consumer

A console consumer can be used with the `kafka-console-consumer` Kafka CLI command.  
It is a daemon process that starts waiting for incoming messages in the topic.  
By default, it starts consuming from the time it starts, but we can consume from the beginning with the `--from-beginning` parameter.

We can print some metadata in addition to each message value by using a formatter.

```commandline
// consume messages from now
kafka-console-consumer  --bootstrap-server localhost:9092 --topic test-topic

// consume messages from the beginning
kafka-console-consumer  --bootstrap-server localhost:9092 --topic test-topic --from-beginning

// consume messages and display metadata
kafka-console-consumer  --bootstrap-server localhost:9092 --topic test-topic --from-beginning
                        --formatter kafka.tools.DefaultMessageFormatter --property timestamp.print=true
                        --property key.print=true --property print.partition=true
```
 
If the topic has multiple partitions, messages within a partition are consumed in order, but no order is guaranteed for messages between partitions.

We can use the `--group <GROUP_NAME>` parameter to include the consumer in a consumer group.  
All consumers started with the same group name will be part of the same consumer group.  
They will all be in charge of a distinct set of partitions of the consumed topic.  

Consumer groups can be managed with the `kafka-consumer-groups` CLI command.  
It supports the `--list` and the `--describe` commands.

```commandline
// list all consumer groups
kafka-consumer-groups --bootstrap-server localhost:9092 --list

// describe a consumer group (topic, partition, offset...)
kafka-consumer-groups --bootstrap-server localhost:9092 --describe --group my-group
```


## Kafka Java Programming

The official SDK for Kafka is in Java, but the Kafka community has created an SDK for most other languages (Scala, C++, Python, JS...).

### Project Setup

Ensure a recent JDK is installed, for example AWS Corretto.   

Create a new IntelliJ IDEA project using Gradle (Groovy) : `New Project > Java > Gradle (Groovy)`

Create a new module under the project : `right-click on project > New Module > Java + Gradle > set artifact name`  
The artifact name can be anything, for example `com.tuto.kafka`

Add the Kafka and SLF4J dependencies to the `build.gradle` file :
- type "Kafka Maven" on Google and open the `org.apache.kafka` Maven Repository result
- choose `kafka-clients`, pick the latest version (3.4.0 now) and select the `Gradle(Short)` tab
- copy the import code and add it in the `build.gradle` file in the `dependencies{}` block
- same steps for `slf4j-api` and `slf4j-simple` (replace `testImplementation` by `implementation`)
- remove junit dependencies
- open the Gradle tab on the right of IntelliJ, and click the Reload icon to import the Kafka and SLF4 jars
- ensure Kafka and SLF4J jars appear in the project tree under "External libraries"


### Producer Process

To send data to a cluster in Java, we use the generic `KafkaProducer` class.  
It is configured with a `Properties` object that receives the connection and producer properties.  
It must specify what serializers to use for the message key and value.  
It can send generic objects of type `ProducerRecord` to Kafka.

```java
    public static void main(String[] args) {
    
        // create the properties for the producer
        Properties properties = new Properties();
        // connection property
        properties.setProperty("bootstrap.servers", "localhost:9092");
        // set producer properties
        properties.setProperty("key.serializer", StringSerializer.class.getName());
        properties.setProperty("value.serializer", StringSerializer.class.getName());

        // create the producer
        KafkaProducer<String, String> producer = new KafkaProducer<>(properties);

        // create a producer record with an optional key
        ProducerRecord<String, String> record = new ProducerRecord<>("demo_topic", "key1", "Hello World");

        // send the record to Kafka
        // we can pass an optional callback executed after the record is sent
        producer.send(record, (metadata, e) -> {
            if (e == null) {
                // record successfully sent
                log.info("Sent record :"
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
    }
```


### Consumer Process

A Kafka consumer is created in Java with the generic class `KafkaConsumer`.  
It also receives a `Properties` object for its configuration, and can belong to a consumer group.  
It can subscribe to a list of topics with `consumer.subscribe()`.  
It retrieves messages or wait for new ones with the `consumer.poll()` method.

To handle shutdown gracefully, it needs to use a shutdown hook.  
The hook calls the `consumer.wakeup()` method, so it will throw a `WakeupException` that gets caught in the main thread.

```java
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
    consumer.subscribe(Arrays.asList("demo_topic"));

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
}
```