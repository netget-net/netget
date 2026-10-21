//! HDFS NameNode and DataNode server tests. The peers (Apache Hadoop 3.5.0's `hdfs` CLI and
//! colinmarc/hdfs's Go client) are required: a test fails, naming how to install them, when
//! they are absent. `wire_test` needs nothing but tshark for its oracle.
pub mod go_client_test;
pub mod hadoop_cli_test;
pub mod support;
pub mod wire_test;
