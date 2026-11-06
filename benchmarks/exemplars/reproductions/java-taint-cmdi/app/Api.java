package app;
public class Api {                                             // entry point
    public void ping(String host) throws Exception { new ShellService().runPing(host); }
}
