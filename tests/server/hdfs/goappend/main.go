// netget-hdfs-append: standard input appended to an HDFS file through colinmarc/hdfs v2.4.0's
// own Client.Append (its append request, its block writer reopening a partial last block with
// PIPELINE_SETUP_APPEND and aligning to the next chunk, its updateBlockForPipeline, addBlock
// and complete). The library's hdfs command has no append subcommand, so this is the smallest
// driver that reaches that code: it adds no protocol logic of its own.
//
// Usage: HADOOP_NAMENODE=host:port HADOOP_USER_NAME=user netget-hdfs-append /path < data
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/colinmarc/hdfs/v2"
)

func fail(step string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
	os.Exit(1)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: netget-hdfs-append /path < data")
		os.Exit(2)
	}
	client, err := hdfs.NewClient(hdfs.ClientOptions{
		Addresses: []string{os.Getenv("HADOOP_NAMENODE")},
		User:      os.Getenv("HADOOP_USER_NAME"),
	})
	if err != nil {
		fail("connect", err)
	}
	w, err := client.Append(os.Args[1])
	if err != nil {
		fail("append", err)
	}
	n, err := io.Copy(w, os.Stdin)
	if err != nil {
		fail("write", err)
	}
	if err := w.Close(); err != nil {
		fail("close", err)
	}
	fmt.Printf("appended %d bytes\n", n)
}
