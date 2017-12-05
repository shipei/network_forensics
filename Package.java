import java.util.*;

public class Package {

    IPv4 ipv4;
    Protocol protocol;
    HTTP http;
    public Package(byte[] bytes) {       
        int IHL = (Utility.bytesToDecimal(Arrays.copyOfRange(bytes, 30, 31)) & 0xf) * 4;
        this.ipv4 = new IPv4(Arrays.copyOfRange(bytes, 30, 30+IHL));
        if(this.ipv4.protocol == 17) {
            
            this.protocol = new UDP(Arrays.copyOfRange(bytes, 30+IHL, 38+IHL)); 
            this.http = new HTTP(Arrays.copyOfRange(bytes, 38+IHL, 30+this.ipv4.total_length));
        } else if(this.ipv4.protocol == 6) {          
            this.protocol = new TCP(Arrays.copyOfRange(bytes, 30+IHL, 50+IHL));
            this.http = new HTTP(Arrays.copyOfRange(bytes, 30+IHL+((TCP)this.protocol).THL*4, 30+this.ipv4.total_length));
        } else { 
            this.protocol = null;
            this.http = null;
        }
    }
}