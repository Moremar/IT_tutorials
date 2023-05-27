# Hadoop Tutorial

## Big Data

An IT problem is considered "Big Data" if the quantity of data exceeds what a relational database or a single machine can handle.  
There is no strict limit, most businesses would consider it above hundreds of TB of data.  
A good indicator of a Big Data problem is the 3 Vs : high **Volume**, high **Velocity** (data growth), high **Variety** of data.

Many real-life problems need Big Data tools :
- the NASA (National Aeronautics and Space Administration) gathers 1.7GB/hour of data from their observations
- Ebay has a 40PB Hadoop cluster
- FB generates 130TB/day of log ...

Big Data problems bring multiple challenges :
- **storage** : must be distributed across multiple machines
- **computational efficiency** : cannot load all data in memory to perform calculation
- **data loss prevention** : require data replication in case of machine failure
- **financial cost** of storage and computation (time, electricity, machines...)


## Hadoop Introduction

RDBMS are not horizontally scalable, they run on a single host and are not distributed.  
They are designed to process structured data, and do not work well with unstructured or nested data, or with various data types (text + image).  

Hadoop, developed in 2008, is a framework for distributed processing of large data sets across clusters of commodity computers.  
It offers a solution to big data problems :

- support huge data volume
- storage-efficient
- good data recovery
- horizontal scaling
- cost effective
- easy to develop on it
  

Hadoop uses a dedicated file system called HDFS (Hadoop Distributed File System).  
HDFS manages the storage, splitting the files into blocks, replicating each block to prevent data loss, and keeping track of which block is in each node.  

For the distributed computation, Hadoop uses MapReduce, bringing intermediate results from every node together and generating a consolidated output.  


## Hadoop Distributed File System (HDFS)

### Existing file systems
A file system controls how data is stored and retrieved.  
It stores metadata about files and folders, manages storage space, and permissions and security.

- **FAT32** (File Allocation Table) : old Microsoft FS, 4GB file limit, 32GB volume limit
- **NTFS** (New Technology File System) : new Microsoft FS, 16EB file and volume limit, it has a 4KB block size, so a file's actual size will be a multiple of 4KB (even if it contains just one byte)
- **HFS** (Hierarchical File System) : old Apple FS,  2GB file limit, 2TB volume limit
- **HFS+** : successor of HFS, 8EB file and volume limit
- **APFS** (Apple File system, most recent FS from Apple (2017)
- **ext3** : most popular Linux FS, 2TB file limit, 32TB volume limit
- **ext4** : successor of ext3, 16TB file limit, 1EB volume limit

These file systems cannot be used for Big Data, as they only manage the files on a given machine.  
That is why Hadoop uses its own file system HDFS to run its cluster over multiple nodes.  

HDFS has a distributed view of all the blocks across all nodes of the cluster, not only on the local FS.  
The distributed view is required to know what blocks to replicate on what node.

HDFS is a file system running above the local FS of the machine (ext4 for linux for example).  
It does not replace the local FS, it uses it for the actual file storage, but adds a distributed management layer above it.

HDFS splits files into blocks of size 128MB or 256MB, dispatches the blocks across nodes and ensures block replication.  
The block size of HDFS is much bigger than the block size in NTFS (4KB).  
HDFS uses the underlying FS, so when saving a file the "lost" space due to block size is the one from the underlying FS (4KB).  
The big block size in HDFS allows to have file data in contiguous space in memory, speeding up their retrieval.  

Commands to interact with the HDFS cluster start with `hadoop fs` :

```
# List the top-level folder of the Hadoop cluster (file name, replication factor, creation time...)
hadoop fs -ls /

// Create a folder in the Hadoop cluster
hadoop fs -mkdir hadoop-test

// Copy a file from the local FS to the Hadoop FS
hadoop fs -copyFromLocal ./file.txt hadoop-test/

// Copy a file from the Hadoop FS to the local FS
hadoop fs -copyToLocal hadoop-test/file.txt . 

// Show details about a file on Hadoop FS (number of blocks, nodes containing it, replications...)
hdfs fsck <file> -files -blocks -locations
```
Listing files in Hadoop shows a different output from `ls /` since it has a view across the entire cluster and only shows what is relevant to the Hadoop cluster.  
The output of `hadoop fs -ls /` is the same on any node of the cluster.  

Hadoop blocks and their metadata are stored in the underlying FS under a location configured by the Hadoop admin in the `/etc/hadoop/conf/hdfs-site.xml` config file.  
HDFS knows how to make sense of these blocks, but the underlying FS sees only blocks and doesn't know how to reconstruct the files.

The `-copyToLocal` command is a READ operation on the Hadoop cluster.  
HDFS is structured to have a single name-node (master) and many data nodes (slaves).  
The local server sends a request to the name-node to know the blocks of the requested file and where to find them.  
The name-node replies with the name of each block, and the nodes storing it, sorted by proximity order (same node > same rack > other rack).  
The local server then requests each block to the closest node having it, or the next one if a node is not responsive.

The `-copyFromLocal` is a WRITE operation on the Hadoop cluster.  
The local server sends a request to the name-node to ask if it can create the file.  
The name-node checks permission and file existence, and responds with the block names and the nodes to store them.  
The local server then sends the blocks to the nodes, waiting for the ACK of each block before sending the next one. 


## MapReduce

MapReduce is a distributed programming model to process large dataset in parallel.  
Hadoop MapReduce is an implementation of the MapReduce model.

A MapReduce job splits the data-set into independent chunks called "input splits", each processed in parallel by a dedicated mapper.    
A mapper code can be written in any language (Java, Scala, Python...).  
It runs once for each record in its input split, and generates a KV pair for each record.  
The output of a mapper is a list of KV pairs (one per record of the input split).

After the map phase comes the shuffle phase, where the output of all mappers are grouped by key (a list of values for each key), and passed as input to the reducers.  

The reducer reduces all values for a given key into a single value.  

Optionally we can have a combiner after the mapper, that reduces the values generated by a single mapper.  
It helps reduce the data to transfer to the reducer, and the load on the reducer.  
A combiner performs the same task as the reducer, but only on the output of a given mapper.  
It can use the same binary as the reducer (but sometimes it doesn't work, for example if we want to calculate an average).

A Java MapReduce job is executed on a Hadoop cluster with the command :

```commandline
hadoop jar <JAR file> <main class> <input file> <output file>
```

It returns the result of the calculation, as well as many counters about the job execution.  
Counters include the number of input/output records of the mapper, combiner and reducer phase...

It is possible to add custom counters in the MapReduce job to count relevant info for our task (for example the number of records having a specific value or format).  
The Hadoop API lets us increment a custom counter from the mapper or reducer code, and Hadoop will display the counter value after the job execution.



