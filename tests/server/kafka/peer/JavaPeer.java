// The official Apache Kafka Java client (kafka-clients 3.9.1) against NetGet's broker:
// produce one record and wait for its offset, then assign partition 0, seek to 0 and poll
// until a record arrives. Run as a single-file source program:
//   java -cp kafka-clients-3.9.1.jar:slf4j-api-1.7.36.jar JavaPeer.java <bootstrap> <topic>
// Idempotence is off (InitProducerId is not implemented) and there is no group.id, so the
// consumer needs no coordinator.
import java.time.Duration;
import java.util.List;
import java.util.Properties;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.clients.producer.RecordMetadata;
import org.apache.kafka.common.TopicPartition;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.apache.kafka.common.serialization.StringSerializer;

public class JavaPeer {
    public static void main(String[] args) throws Exception {
        String bootstrap = args[0];
        String topic = args[1];
        Properties p = new Properties();
        p.put("bootstrap.servers", bootstrap);
        p.put("acks", "1");
        p.put("enable.idempotence", "false");
        p.put("linger.ms", "0");
        p.put("max.block.ms", "15000");
        p.put("request.timeout.ms", "10000");
        p.put("delivery.timeout.ms", "20000");
        p.put("key.serializer", StringSerializer.class.getName());
        p.put("value.serializer", StringSerializer.class.getName());
        try (KafkaProducer<String, String> producer = new KafkaProducer<>(p)) {
            RecordMetadata m = producer
                    .send(new ProducerRecord<>(topic, 0, "java-key", "hello from the java client"))
                    .get();
            System.out.println("PRODUCED partition=" + m.partition() + " offset=" + m.offset());
        }
        Properties c = new Properties();
        c.put("bootstrap.servers", bootstrap);
        c.put("enable.auto.commit", "false");
        c.put("request.timeout.ms", "10000");
        c.put("key.deserializer", StringDeserializer.class.getName());
        c.put("value.deserializer", StringDeserializer.class.getName());
        try (KafkaConsumer<String, String> consumer = new KafkaConsumer<>(c)) {
            TopicPartition tp = new TopicPartition(topic, 0);
            consumer.assign(List.of(tp));
            consumer.seek(tp, 0);
            long deadline = System.currentTimeMillis() + 20000;
            while (System.currentTimeMillis() < deadline) {
                for (ConsumerRecord<String, String> r : consumer.poll(Duration.ofMillis(500))) {
                    System.out.println("CONSUMED offset=" + r.offset() + " key=" + r.key() + " value=" + r.value());
                    return;
                }
            }
        }
        System.err.println("no record consumed within 20s");
        System.exit(3);
    }
}
