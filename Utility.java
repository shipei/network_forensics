import java.util.*;
import java.nio.*;

public class Utility {

    public static int bytesToDecimal(byte[] bytes) {
        String binary_str = "";
        if(bytes.length == 0) 
            return -1;
        for(byte b: bytes) {
            binary_str += String.format("%8s", Integer.toBinaryString(b & 0xff)).replace(' ', '0');           
        }
        return Integer.parseInt(binary_str, 2);
    }

    public static long bytesToLong(byte[] bytes) {
        String binary_str = "";
        if(bytes.length == 0) 
            return -1;
        for(byte b: bytes) {
            binary_str += String.format("%8s", Integer.toBinaryString(b & 0xff)).replace(' ', '0');           
        }
        return Long.parseLong(binary_str, 2);
    }

    public static byte[] reverse(byte[] bytes) {
        for(int i = 0; i < bytes.length/2; i++) {
            byte tmp = bytes[i];
            bytes[i] = bytes[bytes.length-i-1];
            bytes[bytes.length-i-1] = tmp;
        }
        return bytes;
    }

    public static int[] bytesToBinary(byte[] bytes) {
        String binary_str = "";
        if(bytes.length == 0) 
            return new int[0];
        for(byte b: bytes) {
            binary_str += String.format("%8s", Integer.toBinaryString(b & 0xff)).replace(' ', '0');
            
        }
        int[] binary_arr = new int[binary_str.length()];
        for(int i = 0; i < binary_str.length(); i++) {
            binary_arr[i] = Character.getNumericValue(binary_str.charAt(i));
        }
        return binary_arr;
    }


    public static String binaryToIp(int[] binary, int opt) {
        
                String IpAddress = "";
                int index = 7;
                int p = 0;
        
                if(opt == 1) {
                    int m = binary.length-8;
                    int count = 0;
                    int new_binary[] = new int[32];
                    for(int i = 0; i < 32; i++) {
                        if(count == 8) {
                            m -= 16;
                            count = 0;
                        }
                        new_binary[i] = binary[m];
                        m++;
                        count++;
                    }
                    for(int i = 0; i < 32; i++) {
                        binary[i] = new_binary[i];
                    }
                }			
                   
                for(int i = 0; i < 4; i++) {
                    int decimal = 0;
                    for(int j = index; j >= index-7; j--) {
                        decimal += binary[j] * Math.pow(2, p);
                        p++;
                    }
                    IpAddress += decimal + ".";
                    p = 0;
                    index += 8;
                }
                StringBuilder sb = new StringBuilder(IpAddress);
                sb.deleteCharAt(IpAddress.length()-1);
                return sb.toString();
        
    }

    public static byte[] concatArray(byte[] arr1, byte[] arr2) {
        int aLen = arr1.length;
        int bLen = arr2.length;
        byte[] ret = new byte[aLen+bLen];
        System.arraycopy(arr1, 0, ret, 0, aLen);
        System.arraycopy(arr2, 0, ret, aLen, bLen);
        return ret;
    }


    public static String bytesToString(byte[] bytes) {
        String ret = "";
        try {
            ret = new String(bytes, "UTF-8");
        } catch(Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    public static int detectHex(String hex_str) {
        try {
            return Integer.parseInt(hex_str, 16);
        } catch (Exception e) {
            return -1;
        }
    }

    public static void main(String[] args) {

        // byte[] bytes = {(byte) 0xdf, (byte) 0x28};
        // byte[] bytes2 = {(byte) 0x81, (byte) 0x4f, (byte)0xf1, (byte)0x3d};
        // byte[] ret = Utility.concatArray(bytes, bytes2);
        // for(byte b: ret) {
        //     System.out.println(b & 0xff);
        // }
        // System.out.println(Utility.bytesToString(bytes));

        // byte[] revsersed = Utility.reverse(bytes);
        // for(int i = 0; i < revsersed.length; i++) {
        //     System.out.println(revsersed[i] & 0xff);
        // }
        // System.out.println(Utility.binaryToIp(bytesToBinary(bytes), 0));
        // System.out.println(bytes);
        // System.out.println(bytes.toString());
        // String s = new String(bytes);
        // System.out.println(s);
    }
}