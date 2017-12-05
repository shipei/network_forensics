import java.io.*;
import java.util.*;

public class Wireshark {

    public Wireshark() {
    }

    // task 1:
    public void pcapParsing(byte[] bytes) {
        int pkg_num, ip_num, tcp_num, udp_num, tcp_conn_num;
        pkg_num = ip_num = tcp_num = udp_num = tcp_conn_num = 0;
        int i = 0, pkg_len;
        HashSet<String> conns = new HashSet<>(); //TCP connections set ex.(p1 + " " + p2)
        while(i+12 <= bytes.length) {          
            // extract package length from package header 
            pkg_len = Utility.bytesToDecimal(Utility.reverse(Arrays.copyOfRange(bytes, i+8, i+12)));
            if(pkg_len == 0)
                break;   
            // extract type (IPv4 or not) from Ethernet header
            int type = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, i+28, i+30));
            pkg_num += 1; //updating pkg counter
            if(type == 2048) { //type: IPv4 (0x0800)
                ip_num += 1; //updating IPv4 counter

                // creating a new pkg from pkg header to end of pkg
                Package pkg = new Package(Arrays.copyOfRange(bytes, i, i+16+pkg_len)); 
                
                if(pkg.ipv4.protocol == 6) { //TCP
                    tcp_num += 1; //updating tcp counter
                    String conn =  pkg.ipv4.source_address + " " 
                                    + Integer.toString(((TCP)pkg.protocol).source_port) + " " 
                                    + pkg.ipv4.destination_address + " "
                                    + Integer.toString(((TCP) pkg.protocol).destination_port);

                    // task 1:check bidirection
                    String reversed_conn = pkg.ipv4.destination_address + " " 
                                        + Integer.toString(((TCP)pkg.protocol).destination_port) + " " 
                                        + pkg.ipv4.source_address + " "
                                        + Integer.toString(((TCP)pkg.protocol).source_port);

                    if(!conns.contains(conn) && !conns.contains(reversed_conn)) {
                        conns.add(conn);
                        tcp_conn_num += 1; //updating tcp connection counter
                    } 
                } else if(pkg.ipv4.protocol == 17) //UDP
                        udp_num += 1;
            }
            i += 16+pkg_len; //updating starting point of pkg (pkg header)
        }

        // task 1 : printing results
        System.out.println(Integer.toString(pkg_num) + " " + Integer.toString(ip_num) + " "
        + Integer.toString(tcp_num) + " " + Integer.toString(udp_num) + " " 
        + Integer.toString(tcp_conn_num));

    }

    // task 2:
    public void assembleTCP(byte[] bytes) {
        int i = 0, pkg_len;
        TreeMap<String, TreeMap<Long, byte[]>> tcp_map = new TreeMap<>();

        while(i+12 <= bytes.length) {          
            // extract package length from package header 
            pkg_len = Utility.bytesToDecimal(Utility.reverse(Arrays.copyOfRange(bytes, i+8, i+12)));
            if(pkg_len == 0)
                break;   
            // extract type (IPv4 or not) from Ethernet header
            int type = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, i+28, i+30));
            // ws.pkg_num += 1; //updating pkg counter
            if(type == 2048) { //type: IPv4 (0x0800)
                // creating a new pkg from pkg header to end of pkg
                Package pkg = new Package(Arrays.copyOfRange(bytes, i, i+16+pkg_len)); 
                
                if(pkg.ipv4.protocol == 6) { //TCP
                    // DEBUG:
                    // if(pkg.ipv4.destination_address.equals("140.182.214.80") && ((TCP)pkg.protocol).destination_port == 52782){
                    //     System.out.println("range : "+0+" , "+(16+pkg_len));
                    //     System.out.println("!!\n "+ pkg.data.content.length +"  \n!!");
                    //     System.out.println("IPV4 heade length : " + pkg.IHL);
                    //     System.out.println("package length  : " + pkg_len);
                    //     System.out.println(Arrays.copyOfRange(bytes, i+8, i+12));
                    //     System.out.println("pkg length" + (16+pkg_len));

                    //     System.out.println((TCP)pkg.protocol);
                    // }
                    
                    String conn =  pkg.ipv4.source_address + " " 
                                    + Integer.toString(((TCP)pkg.protocol).source_port) + " " 
                                    + pkg.ipv4.destination_address + " "
                                    + Integer.toString(((TCP) pkg.protocol).destination_port);


                    // task 2 step 1: adding data to treemap
                    if(((TCP)pkg.protocol).source_port == 80 || ((TCP)pkg.protocol).destination_port == 80) {
                        if(!tcp_map.containsKey(conn)) {
                            TreeMap<Long, byte[]> val = new TreeMap<>();
                            val.put(((TCP)pkg.protocol).sequence_number, pkg.http.content);
                            tcp_map.put(conn, val);
                        } else {
                            // if(!tcp_map.get(conn).containsKey(((TCP)pkg.protocol).sequence_number)) {
                                // tcp_map.get(conn).put(((TCP)pkg.protocol).sequence_number, ((TCP)pkg.protocol).data);
                            // }
                            if(tcp_map.get(conn).containsKey(((TCP)pkg.protocol).sequence_number)) {
                                byte[] orig_data = tcp_map.get(conn).get(((TCP)pkg.protocol).sequence_number);
                                // ((TCP)pkg.protocol).data (new data)
                                tcp_map.get(conn).put(((TCP)pkg.protocol).sequence_number, Utility.concatArray(orig_data, pkg.http.content));
                            } else {
                                tcp_map.get(conn).put(((TCP)pkg.protocol).sequence_number, pkg.http.content); 
                            }
                        }
                    }

                } //else if(pkg.ipv4.protocol == 17) //UDP
                        // ws.udp_num += 1;
            }
            i += 16+pkg_len; //updating starting point of pkg (pkg header)
        }
           // task 2 step 2: print tcp_num lines of six numbers, uplink data and downlink data
           String tcp_data = ""; //the whole data for uplink data and downlink data
           for(Map.Entry<String, TreeMap<Long, byte[]>> ent: tcp_map.entrySet()) {
               TreeMap<Long, byte[]> val = ent.getValue();
               
               String conn = ent.getKey();
               // split tcp_conn to: source_addr, source_port, dest_addr, dest_port
               String[] infos = conn.split(" ");
               
               int uplink_len = 0; //uplink stream length
               if(Integer.parseInt(infos[3]) == 80) { //destination port is 80 (server side)     
                   for(Map.Entry<Long, byte[]> val_ent: val.entrySet()) {
                       uplink_len += val_ent.getValue().length; //adding up uplink stream length
                       tcp_data += Utility.bytesToString(val_ent.getValue()); // concatnating tcp_data string
                   }
   
                   String downlink_conn = infos[2] + " " 
                   + infos[3] + " " 
                   + infos[0] + " "
                   + infos[1];
                   
                   int downlink_len = 0; //downlink stream length
                   if(tcp_map.containsKey(downlink_conn)) {
                       TreeMap<Long, byte[]> downlink_val = tcp_map.get(downlink_conn);
                       for(Map.Entry<Long, byte[]> downlink_ent: downlink_val.entrySet()) {
                           downlink_len += downlink_ent.getValue().length; //adding up downlink stream length
                           tcp_data += Utility.bytesToString(downlink_ent.getValue()); // concatnating tcp_data string
                       }
                   }
                   System.out.println(conn + " " + uplink_len + " " + downlink_len); // print out uplink length and downlink length
               }
           }
           System.out.print(tcp_data); // print out uplink data and downlink data
    }

    // return tcp map from assembleTCP (needed for task 3)
    public TreeMap<String, TreeMap<Long, byte[]>> get_https(byte[] bytes) {
        int i = 0, pkg_len;
        TreeMap<String, TreeMap<Long, byte[]>> tcp_map = new TreeMap<>();
        while(i+12 <= bytes.length) {          
            pkg_len = Utility.bytesToDecimal(Utility.reverse(Arrays.copyOfRange(bytes, i+8, i+12)));
            if(pkg_len == 0)
                break;   
            int type = Utility.bytesToDecimal(Arrays.copyOfRange(bytes, i+28, i+30));
            if(type == 2048) { //type: IPv4 (0x0800)
                Package pkg = new Package(Arrays.copyOfRange(bytes, i, i+16+pkg_len)); 
                if(pkg.ipv4.protocol == 6) { //TCP
                    String conn =  pkg.ipv4.source_address + " " 
                                    + Integer.toString(((TCP)pkg.protocol).source_port) + " " 
                                    + pkg.ipv4.destination_address + " "
                                    + Integer.toString(((TCP) pkg.protocol).destination_port);

                    if(((TCP)pkg.protocol).source_port == 80 || ((TCP)pkg.protocol).destination_port == 80) {
                        if(!tcp_map.containsKey(conn)) {
                            TreeMap<Long, byte[]> val = new TreeMap<>();
                            val.put(((TCP)pkg.protocol).sequence_number, pkg.http.content);
                            tcp_map.put(conn, val);
                        } else {
                            if(tcp_map.get(conn).containsKey(((TCP)pkg.protocol).ack_number)) {
                                byte[] orig_data = tcp_map.get(conn).get(((TCP)pkg.protocol).ack_number);
                                tcp_map.get(conn).put(((TCP)pkg.protocol).ack_number, Utility.concatArray(orig_data, pkg.http.content));
                            } else {
                                tcp_map.get(conn).put(((TCP)pkg.protocol).ack_number, pkg.http.content); 
                            }
                        }
                    }

                } 
            }
            i += 16+pkg_len; //updating starting point of pkg (pkg header)
        }
        return tcp_map;
    }

    // task 3: Extract HTTP Conversations
    public void extractHTTP(byte[] bytes) {
        String requested_URL, host_name, response_code;
        requested_URL = host_name = response_code = "";
        int body_len = 0;
        // ordered_https: reception time -> requested_URL + " " + host_name + " " + response_code + " " + body_len
        TreeMap<String, String> ordered_https = new TreeMap<>(); 
        
        Wireshark ws = new Wireshark();
        TreeMap<String, TreeMap<Long, byte[]>> tcp_data = ws.get_https(bytes);      

        TreeMap<String, byte[]> requests = new TreeMap<>();
        TreeMap<String, byte[]> responses = new TreeMap<>();
        for(Map.Entry<String, TreeMap<Long, byte[]>> ent: tcp_data.entrySet()) {
            String conn = ent.getKey();
            String[] infos = ent.getKey().split(" ");
            if(infos[3].equals("80")) { // uplink
                for(Map.Entry<Long, byte[]> val_ent: ent.getValue().entrySet()) {
                    if(!requests.containsKey(conn)) {
                        requests.put(conn, val_ent.getValue());
                    } else {
                        byte[] orig_data = requests.get(conn);
                        requests.put(conn, Utility.concatArray(orig_data, val_ent.getValue()));
                    }
                }    
                // find downlink four-tuple:
                String down_conn = infos[2] + " " + infos[3] + " " + infos[0] + " " + infos[1];
                if(tcp_data.containsKey(down_conn)) {
                    for(Map.Entry<Long, byte[]> down_ent: tcp_data.get(down_conn).entrySet()) {
                        if(!responses.containsKey(down_conn)) {
                            responses.put(down_conn, down_ent.getValue());
                        } else {
                            byte[] orig_data = responses.get(down_conn);
                            responses.put(down_conn, Utility.concatArray(orig_data, down_ent.getValue()));
                        }
                    }
                }
            }
        }
        // // DEBUG: 
        // for(Map.Entry<String, byte[]> up_ent: requests.entrySet()) {
        //     System.out.println("**************STARTING DATA********************");
        //     System.out.println(Utility.bytesToString(up_ent.getValue()));
        //     System.out.println("**************ENDING DATA********************");
        // }
        // System.out.println("**************SEPERATE LINE********************");
        // for(Map.Entry<String, byte[]> down_ent: responses.entrySet()) {
        //     System.out.println("**************STARTING DATA********************");
        //     System.out.println(Utility.bytesToString(down_ent.getValue()));
        //     System.out.println("**************ENDING DATA********************");
        // }
        // for(Map.Entry<String, TreeMap<Long, byte[]>> ent: tcp_data.entrySet()) {
        //     for(Map.Entry<Long, byte[]> ent2: ent.getValue().entrySet()) {
        //         System.out.println("\n**********BEGINNING OF DATA***********\n");
        //         System.out.println(Utility.bytesToString(ent2.getValue()));
        //         System.out.println("**********END OF DATA***********\n\n");
        //     }
        // }
        
        // int count = 0;
        ArrayList<String> methods = new ArrayList<>(Arrays.asList("GET", "PUT", "HEAD", "POST", "DELETE"));

        for(Map.Entry<String, TreeMap<Long, byte[]>> entry: tcp_data.entrySet()) {
            for(Map.Entry<Long, byte[]> val_ent: entry.getValue().entrySet()) {
                String http_content = Utility.bytesToString(val_ent.getValue()); // retrieve http content for each tcp connection
                if(http_content.length() == 0) continue;
                
                String[] http_content_arr = http_content.split("\n"); // split http content by lines 
                if(methods.contains(http_content_arr[0].substring(0, 3)) || methods.contains(http_content_arr[0].substring(0, 4))
                || methods.contains(http_content_arr[0].substring(0, 6))) { // if first n characters are a request method
                    // count += 1;
                    String[] fst_ln_ele = http_content_arr[0].split(" ");
                    requested_URL = fst_ln_ele[1];
                    if(http_content_arr[1].substring(0, 6).equals("Host: ")) {
                        host_name = http_content_arr[1].substring(6, http_content_arr[1].length());
                    }
                    String[] up_infos = entry.getKey().split(" ");
                    String down_conn = up_infos[2] + " " + up_infos[3] + " " + up_infos[0] + " " + up_infos[1];
                    if(responses.containsKey(down_conn)) {
                        String downlink_content = Utility.bytesToString(responses.get(down_conn));
                        // String[] downlink_content_arr = downlink_content.split("\n");
                        if(downlink_content.substring(0, 8).equals("HTTP/1.1")) {
                            String[] downlink_content_arr = downlink_content.split("\n");
                            String[] first_ln_arr = downlink_content_arr[0].split(" ");
                            response_code = first_ln_arr[1];
                            for(String line: downlink_content_arr) {
                                if(line.contains("Content-Length:")) {
                                    String[] ele = line.split(" ");
                                    try {
                                        body_len = Integer.parseInt(ele[1].replace("\n", "").replace("\r", ""));
                                    } catch (Exception e) {}
                                }
                                if(line.contains("Transfer-Encoding:")) {
                                    String[] ele = line.split(" ");
                                    if(ele[1].contains("chunked")) {
                                        for(String sub_line: downlink_content_arr) {
                                            sub_line = sub_line.replace("\n", "").replace("\r", "");
                                            if(Utility.detectHex(sub_line) != -1) {
                                                body_len += Utility.detectHex(sub_line);
                                            }
                                            
                                        }
                                        
                                    }
                                }
                            }
                        }
                        

                    }
                    System.out.printf("%s %s %s %s \n",requested_URL,host_name.replace("\n", "").replace("\r" ,""),response_code, Integer.toString(body_len));
                    // count ++;
                    
                    body_len = 0;
                    response_code = "";
                } 
            }
        }
        // System.out.println(count);
    }
 

    public static void main(String[] args) {
        // writing .pcap to byte array
        ByteArrayOutputStream pkgs = new ByteArrayOutputStream();
        byte[] buffer = new byte[32*1024];
        int bytesread;
        try {
            while((bytesread = System.in.read(buffer)) > 0) {
                pkgs.write(buffer, 0, bytesread);
            }
        } catch (Exception e)  {
            System.out.println("reading file error.");
            //e.printStackTrace();
        }

        Wireshark ws = new Wireshark();
        byte[] bytes = pkgs.toByteArray();
        bytes = Arrays.copyOfRange(bytes, 24, bytes.length); //taking off header: first 24 bytes.

        try {
            int num = Integer.parseInt(args[0]);
            if(num == 1) {
                ws.pcapParsing(bytes); // task 1
            } else if(num == 2) {
                ws.assembleTCP(bytes); //task 2
            } else if(num == 3) {
                ws.extractHTTP(bytes); //task 3
            }
        } catch (NumberFormatException e) {
            System.out.println("argument should be an integer.");
            System.exit(1);
        }


    }
}