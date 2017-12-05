import java.util.*;
public class UDP extends Protocol {
    int source_port;
    int destination_port;
    int length; 
    int checksum;

    //bytes already has packages header and IPv4 header taking off
    public UDP(byte[] bytes) {
        this.source_port = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 0, 2));
        this.destination_port = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 2, 4));
        this.length = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 4, 6));
        this.checksum = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 6, 8));
    }
}