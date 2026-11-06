namespace app;
public class RealShell : IShell {
    public void Run(string cmd) { System.Diagnostics.Process.Start("/bin/sh", "-c " + cmd); }  // CWE-78
}
