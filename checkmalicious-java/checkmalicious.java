package checkmalicious;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

public class checkmalicious {
    public static void main(String[] args) {
    	// read file 
        String file1Content = readFile("/home/student/Desktop/anurag/data");
        String file2Content = readFile("/home/student/Desktop/anurag/malicious");

        System.out.println(file1Content);
        System.out.println(file2Content);
        
        // create 2d array to store malicious.txt
        // each row in the array contains ipaddress with respective port number and protocol
        String[][] data = parseData(file2Content);
        // check if any ipaddress, port number, protocol from malicious.txt exist in data.txt
        checkMalicious(file1Content, data);
    }
    
    public static String readFile(String fileName) {
        StringBuilder content = new StringBuilder();
        try {
            File file = new File(fileName);
            Scanner sc = new Scanner(file);
            while (sc.hasNextLine()) {
                content.append(sc.nextLine()).append("\n");
            }
            sc.close();
        } catch (FileNotFoundException e) {
            System.err.println("File not found: " + fileName);
        }
        return content.toString();
    }

    public static String[][] parseData(String content) {
        String[] lines = content.split("\n");
        String[][] data = new String[lines.length - 1][3];

        for (int i = 1; i < lines.length; i++) {
        	// ip, port, protocol is separated by space so use split
            String[] parts = lines[i].split(" "); 
            data[i - 1][0] = parts[0]; // store IP address in 0th column
            data[i - 1][1] = parts[1]; // store Port number in 1st column
            data[i - 1][2] = parts[2]; // store Protocol in 2nd column
        }

        return data;
    }

    public static void checkMalicious(String file1Content, String[][] data) {
        for (String[] row : data) {
            String ip = row[0];
            String port = row[1];
            String protocol = row[2];

            boolean ipFound = file1Content.contains("Source IP: " + ip) ||
                              file1Content.contains("Destination IP: " + ip);
            boolean portFound = file1Content.contains("Src Port: " + port) ||
                                file1Content.contains("Dst Port: " + port);
            boolean protocolFound = file1Content.toLowerCase().contains(protocol.toLowerCase());

            if (ipFound && portFound && protocolFound) {
                System.out.println("Match found: IP = " + ip + ", Port = " + port + ", Protocol = " + protocol);
                return;
            }
        }
        // if no match found the file is not malicious
        System.out.println("Match not found, file is not malicious");
    }
}
