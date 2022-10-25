import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
 
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

class result {
    private final int port;
    private final boolean isOpen;

    result(int p, boolean b) {
        this.port = p;
        this.isOpen = b;
    }

    public int givePort() {
        return this.port;
    }

    public boolean giveStatus() {
        return this.isOpen;
    }
}

public class ScannerCLI {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES";

    // This function will try to get local network IPs of this machine
    public ArrayList<String> getMyIps() {
        ArrayList<String> ips = new ArrayList<String>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                // filters out 127.0.0.1 and inactive interfaces
                if (iface.isLoopback() || !iface.isUp())
                    continue;
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    // *EDIT*
                    if (addr instanceof Inet6Address)
                        continue;
                    ips.add(addr.getHostAddress());
                }
            }
        } catch (Exception e) {}
        return ips;
    }

    // This function takes ip and port and try to connect to it 
    public Future<result> portIsOpen(final ExecutorService es, String ip, int port) {
        return es.submit(new Callable<result>() {
            @Override
            public result call() {
                result rl = new result(port, false);
                try {
                    Socket soc = new Socket();
                    soc.connect(new InetSocketAddress(ip, port), 200); // timeout 2.0 sec
                    soc.close();
                    rl = new result(port, true);
                    return rl;
                } catch (Exception e) {
                    return rl;
                }
            }
        });
    }

    // This function will take the host and list of ports to scan if they are open or not
    public HashMap<Integer, Boolean> checkPorts(String host, ArrayList<Integer> portsToScan) {

        HashMap<Integer, Boolean> ports = new HashMap<>();
        final ExecutorService es = Executors.newFixedThreadPool(20); // run 20 threads.
        final List<Future<result>> futures = new ArrayList<>();
        
        if (portsToScan!=null&&portsToScan.size()>0){
            for(Integer port:portsToScan){
                futures.add(portIsOpen(es, host, port.intValue()));
            }
        }else{
            // if no speecific ports will scan for all ports [1-65535]
            for(int i=1;i<=65535;i++){
                futures.add(portIsOpen(es, host, i));
            }
        }

        es.shutdown();
        // printing open ports .
        for (final Future<result> f : futures) {
            try {
                if (f.get().giveStatus()) {
                    ports.put(new Integer(f.get().givePort()), new Boolean(true));
                } else {
                    ports.put(new Integer(f.get().givePort()), new Boolean(false));
                }
            } catch (Exception e) {}
        }
        return ports;
    }

    // This function will take a subnet as input and scan all IPs for reachablilty [ with 2 seconds timeout ]
    public HashMap<String, Boolean> checkDevices(String subnet) {
        HashMap<String, Boolean> devices = new HashMap<String, Boolean>();
        try {
            PrintStream original = System.out;
            System.setOut(new PrintStream(new FileOutputStream("/dev/null")));

            IntStream.rangeClosed(1, 254).mapToObj(num -> subnet + num).parallel()
                    .filter((addr) -> {
                        try {
                            if (InetAddress.getByName(addr).isReachable(2000)) {
                                devices.put(addr, new Boolean(true));
                                return true;
                            }
                            return false;
                        } catch (IOException e) {
                            devices.put(addr, new Boolean(false));
                            return false;
                        }
                    }).forEach(System.out::println);
            System.setOut(original);
        } catch (Exception e) {}
        return devices;
    }


    public HashMap<String,ArrayList<Integer>> scanSubnet(String subnet, ArrayList<Integer> portsToScan){
        HashMap<String,ArrayList<Integer>> subnetResults = new HashMap<>();
        // This will give us all network devices with this format {IP: -true/false- for connectivity}
        System.out.println("Going to Scan This Subnet "+subnet);
        HashMap<String, Boolean> subnetDevices = checkDevices(subnet);

        System.out.println("Alive Hosts : "+subnetDevices);
        // Will loop on the active devices to check targeted ports
        subnetDevices.entrySet().forEach(entry -> {
            if (entry.getValue()) {
                ArrayList<Integer> openPorts = new ArrayList<>(); 
                // This will give us all ports with this format {PORT: -tue/false- if open}
                HashMap<Integer, Boolean> devicePorts = checkPorts(entry.getKey().toString(), portsToScan);
                devicePorts.entrySet().forEach(port_entry -> {
                    if (port_entry.getValue()) {
                        openPorts.add(port_entry.getKey());
                    }
                });
                if(openPorts!=null&&openPorts.size()>0){
                    System.out.println("Host "+entry.getKey()+" Has these openPorts "+openPorts);
                    subnetResults.put(entry.getKey(), openPorts);
                } 
            }
            
        });
        return subnetResults;
    }

    
    public boolean dumpResultsToFile(HashMap<String, ArrayList<Integer>> results, boolean encrypt, String key){
        try {
            if(results!=null&&results.size()>0){
                String fileName = "ScanResult"+new SimpleDateFormat("yyyyMMddHHmm'.json'").format(new Date());
                File resultFile=new File(fileName);
                File encryptedFile=new File("Enc"+fileName);
                StringBuilder jsonString = new StringBuilder("{");
                results.entrySet().forEach(entry -> {
                    String hostPorts = "\""+entry.getKey()+"\":[";
                    for(Integer port:entry.getValue()){
                        hostPorts += port+",";
                    }
                    // remove_last comma 
                    StringBuffer sb= new StringBuffer(hostPorts);
                    sb.deleteCharAt(sb.length()-1);
                    sb.append("],");
                    jsonString.append(sb);
                });
                jsonString.deleteCharAt(jsonString.length()-1);
                jsonString.append("}");
    
                FileOutputStream fos=new FileOutputStream(resultFile);
                fos.write(jsonString.toString().getBytes());
                fos.close();
                System.out.println("Clear Text File created at this location : "+resultFile);
                if(encrypt)
                    encryptFile(key, resultFile, encryptedFile);
            }
            
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public ScannerCLI(String appName, String subnet, ArrayList<Integer> ports, boolean encrypt, String keyString) {
        HashMap<String,ArrayList<Integer>> scanResult = null;
        if (subnet!=null&&subnet.length()>0){
            // dump the result from the object to JSON file
            scanResult = scanSubnet(subnet, ports);
            System.out.println("Final Result of the Subnet "+scanResult);
            dumpResultsToFile(scanResult, encrypt, keyString);
        }else{
            // if we are here that means the user didn't enter a subnet -> we will scan whatever we can
            ArrayList<String> mySubnets = new ArrayList<String>();
            scanResult = new HashMap<String,ArrayList<Integer>>();
            ArrayList<String> myIPs = getMyIps();
            for (String ip : myIPs) {
                mySubnets.add(ip.substring(0, ip.lastIndexOf(".")) + ".");
            }
            for (String isubnet : mySubnets) {
                scanResult = (scanSubnet(isubnet, ports));
                dumpResultsToFile(scanResult, encrypt, keyString);
            }
        }

    }

    private static void doCrypto(int cipherMode, String key, File inputFile,
            File outputFile) throws Exception {
        try {
            Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(cipherMode, secretKey);
             
            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);
             
            byte[] outputBytes = cipher.doFinal(inputBytes);
             
            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);
             
            inputStream.close();
            outputStream.close();
             
        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException ex) {
            throw new Exception("Error encrypting/decrypting file", ex);
        }
    }

    public static boolean encryptFile(String key, File inputFile, File outputFile){
        try{
            System.out.println("Encrypting file "+inputFile+" -> result would be in "+outputFile);
            doCrypto(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
        }catch(Exception e){
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public static boolean decryptFile(String key, File inputFile, File outputFile){
        try{
            System.out.println("Decrypting file "+inputFile+" -> result would be in "+outputFile);
            doCrypto(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
        }catch(Exception e){
            e.printStackTrace();
            return false;
        }
        return true;
    }

    public static boolean isValidIPAddressWithoutLastOctect(String ip){
        // Regex for digit from 0 to 255.
        String zeroTo255
            = "(\\d{1,2}|(0|1)\\"
              + "d{2}|2[0-4]\\d|25[0-5])";
        String regex = zeroTo255 + "\\." + zeroTo255 + "\\." + zeroTo255 + "\\.";
        // Compile the ReGex
        Pattern p = Pattern.compile(regex);
        // If the IP address is empty return false
        if (ip == null)
            return false;
        // Pattern class contains matcher() method to find matching between given IP address
        // and regular expression.
        Matcher m = p.matcher(ip);
        // Return if the IP address matched the ReGex
        return m.matches();
    }


    public static void main(String[] args) {
        try{
            Scanner sc = new Scanner(System.in);

            /* Variables Declarations */
            String subnet = "";
            ArrayList<Integer> portsToScan = new ArrayList<>();
            String inputFilePath = "";
            String outputFilePath = "";
            String keyString = "";

            /* User Interaction */
            System.out.println("Welcome to Network Scanner CLI");
            System.out.println("a. Scan Network Subnet");
            System.out.println("b. Encrypt a result file");
            System.out.println("c. Decrypt a result file");
            System.out.print("Please Select an action to perform [a,b,c]: ");
            char choice = sc.next().charAt(0);
            switch(choice){
                case 'a':
                    System.out.print("Would you like to provide details "+
                        "or let the application scan your local network with all ports [true/false]: ");
                    boolean askForInputs = sc.nextBoolean();
                    if(askForInputs){
                        Boolean specificPorts = false;
                        System.out.print("Enter the Subnet you want to scan [fmt:{X.X.X.}]: ");
                        subnet = sc.next();
                        // 6 that is the minimum length for the format
                        if(subnet!=null && subnet.length()>6 && isValidIPAddressWithoutLastOctect(subnet)){ 
                            System.out.print("Do you wish to specify ports or scan all of them [true/false]: ");
                            specificPorts = sc.nextBoolean();
                            if(specificPorts){
                                System.out.println("Keep entering ports to stop enter -1");
                                int port = 0;
                                do{
                                    port = sc.nextInt();
                                    if(port!=-1)
                                        portsToScan.add(port);
                                }while(port!=-1);
                            }
                        }else{
                            System.err.println("Invalid Subnet format");
                            System.exit(-1);
                        }
                    }
                    System.out.print("Do you wish to encrypt the results file [true/false]: ");
                    boolean encrypt = sc.nextBoolean();
                    if(encrypt){
                        System.out.print("Enter the encryption key to encrypt the file with [24 characters or more]: ");
                        keyString = sc.next();
                    }
                    new ScannerCLI("Scanner", subnet, portsToScan, encrypt, keyString);
                    break;
                case 'b':
                    System.out.print("Enter the file location you want to encrypt: ");
                    inputFilePath = sc.next();
                    System.out.print("Enter the file location you want to encrypted file to be created: ");
                    outputFilePath = sc.next();
                    System.out.print("Enter the encryption key to encrypt the file with [24 characters or more]: ");
                    keyString = sc.next();
                    encryptFile(keyString, new File(inputFilePath), new File(outputFilePath));
                    break;
                case 'c':
                    System.out.print("Enter the file location you want to decrypt: ");
                    inputFilePath = sc.next();
                    System.out.print("Enter the file location you want to decrypted file to be created: ");
                    outputFilePath = sc.next();
                    System.out.print("Enter the encryption key that was shared with you to decrypt the file with: ");
                    keyString = sc.next();
                    decryptFile(keyString, new File(inputFilePath), new File(outputFilePath));
                    break;
                default:
                    System.err.println("Invalid choice, stopping the application");
                    System.exit(-1);
            }
            sc.close();
        }catch(Exception e){
            e.printStackTrace();
        }
    }
}
