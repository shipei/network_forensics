import java.util.*;

public class IPv4 {
    int version;
    int IHL;
    int service;
    int total_length;
    int identification;
    int flags;
    int fragment_offset;
    int time;
    int protocol; //6: TCP; 17: UDP
    int checksum;
    String source_address;
    String destination_address;

    //bytes already has packages header taking off
    public IPv4(byte[] bytes) {
        this.version = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 0, 1)) >> 4;
        this.IHL = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 0, 1)) & 0xf;
        this.service = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 1, 2));
        this.total_length = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 2, 4));
        this.identification = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 4, 6));
        this.flags = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 6, 7)) >> 3;
        this.fragment_offset = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 6, 8)) & 0x1fff;
        this.time = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 8, 9));
        this.protocol = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 9, 10));
        this.checksum = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 10, 12));
        this.source_address = Utility.binaryToIp(Utility.bytesToBinary(Arrays.copyOfRange(bytes, 12, 16)), 0);
        this.destination_address = Utility.binaryToIp(Utility.bytesToBinary(Arrays.copyOfRange(bytes, 16, 20)), 0);
    }
}