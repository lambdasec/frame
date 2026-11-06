package app;
public class ShellService {
    public Process runPing(String host) throws Exception {
        return Runtime.getRuntime().exec("ping -c1 " + host);  // CWE-78 sink
    }
}
