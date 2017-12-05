import java.util.*;
public class TCP extends Protocol {
    int source_port;
    int destination_port;
    long sequence_number;
    long ack_number;
    int THL; //tcp header length
    int flags;
    int window;
    int checksum;
    int urgent_ptr;
    // int options;

    //bytes already has packages header and IPv4 header taking off
    public TCP(byte[] bytes) {
        this.source_port = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 0, 2));
        this.destination_port = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 2, 4));
        this.sequence_number = Utility.bytesToLong(Arrays.copyOfRange(bytes, 4, 8));
        this.ack_number = Utility.bytesToLong(Arrays.copyOfRange(bytes, 8, 12));
        this.THL = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 12, 13)) >> 4;
        this.flags = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 12, 14)) & 0xfff;
        this.window = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 14, 16));
        this.checksum = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 16, 18));
        this.urgent_ptr = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 18, 20));
    }

    // DEBUG:
    public String toString(){
        System.out.println("this.source_port      : " + this.source_port);
        System.out.println("this.destination_port : " + this.destination_port);
        System.out.println("this.sequence_number  :" + this.sequence_number);
        System.out.println("this.ack_number       :" + this.ack_number);
        System.out.println("this.THL              :" + this.THL);
        System.out.println("this.flags            :" + this.flags);
        System.out.println("this.window           :" + this.window);
        System.out.println("this.checksum         :" + this.checksum);
        System.out.println("this.urgent_ptr       :" + this.urgent_ptr);
        return "";
    }
}