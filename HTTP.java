import java.util.*;

public class HTTP {

    byte[] content; //the whole bytes for http, used for task 2 
    // attibutes for task 2:
    // String method;
    // String requested_url;
    // String host;
    // String user_agent;

    // int response_code;
    // int content_length;
    // String transfer_encoding;
    // String response_body;
    
    // bytes from ending point of protocol to ending point of data (exclude padding)
    public HTTP (byte[] bytes) {
        this.content = bytes;
        // this.method = "";
        // this.requested_url = "";
        // this.host = "";

    }
}