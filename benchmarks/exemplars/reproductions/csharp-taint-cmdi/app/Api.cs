namespace app;
public class Api {
    private readonly IShell shell;
    public Api(IShell s) { shell = s; }
    public void Ping(string host) { shell.Run("ping -c1 " + host); }   // project reaches the sink here
}
