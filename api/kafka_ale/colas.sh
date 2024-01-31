#!/bin/bash

bin/kafka-topics.sh --delete --topic network-costs --bootstrap-server localhost:9092
bin/kafka-topics.sh --delete --topic network-pids --bootstrap-server localhost:9092
bin/kafka-topics.sh --delete --topic qkd-properties --bootstrap-server localhost:9092
bin/kafka-topics.sh --create --topic network-costs --bootstrap-server localhost:9092
bin/kafka-topics.sh --create --topic network-pids --bootstrap-server localhost:9092
bin/kafka-topics.sh --create --topic qkd-properties --bootstrap-server localhost:9092

