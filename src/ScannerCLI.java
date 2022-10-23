import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;

class result {
    private final int port;
    private final boolean isOpen;
    double timeTaken = 0.00;

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
    private ArrayList<String> mySubnets;

    /**
     * @param appName
     */
    public ScannerCLI(String appName) {

        mySubnets = new ArrayList<String>();
        ArrayList<String> myIPs = getMyIps();
        for (String ip : myIPs) {
            mySubnets.add(ip.substring(0, ip.lastIndexOf(".")) + ".");
        }
        for (String subnet : mySubnets) {
            System.out.println("Checking Subnet "+subnet);
            HashMap<String, Boolean> subnetDevices = checkDevices(subnet);
            subnetDevices.entrySet().forEach(entry -> {
                if (entry.getValue()) {
                    System.out.println("Checking Alive Host Ports : " + entry.getKey());
                    ArrayList<String> openPorts = new ArrayList<String>();
                    HashMap<String, Boolean> devicePorts = checkPorts(entry.getKey().toString());
                    devicePorts.entrySet().forEach(port_entry -> {
                        if (port_entry.getValue()) {
                            openPorts.add(port_entry.getKey());
                        }
                    });
                    if(openPorts.size()>0)
                        System.out.println("OpenPorts : "+openPorts);
                }
            });
        }

    }

    /**
     * @param host
     * @return
     */
    public HashMap<String, Boolean> checkPorts(String host) {

        HashMap<String, Boolean> ports = new HashMap<String, Boolean>();
        final ExecutorService es = Executors.newFixedThreadPool(20); // run 20 threads.
        final List<Future<result>> futures = new ArrayList<>();
        int start = 80, end = 80;
        for (int i = start; i <= end; i++) {
            futures.add(portIsOpen(es, host, i));
        }
        es.shutdown();
        // printing open ports .
        for (final Future<result> f : futures) {
            try {
                if (f.get().giveStatus()) {
                    ports.put("" + f.get().givePort(), new Boolean(true));
                } else {
                    ports.put("" + f.get().givePort(), new Boolean(false));
                }
            } catch (Exception e) {}
        }
        return ports;
    }

    public Future<result> portIsOpen(final ExecutorService es, String ip, int port) {
        return es.submit(new Callable<result>() {
            @Override
            public result call() {
                result rl = new result(port, false);
                long strT = System.currentTimeMillis();
                try {
                    Socket soc = new Socket();
                    soc.connect(new InetSocketAddress(ip, port), 200); // timeout 2.0 sec
                    soc.close();
                    rl = new result(port, true);
                    long te = System.currentTimeMillis() - strT;
                    rl.timeTaken = te / 1000.0;
                    return rl;
                } catch (Exception e) {
                    long te = System.currentTimeMillis() - strT;
                    rl.timeTaken = te / 1000.0;
                    return rl;
                }
            }
        }); // return statement end.
    }

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

    public static void main(String[] args) {
        new ScannerCLI("Scanner");
    }
}
