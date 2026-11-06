package app;
import lib.IStore;
public class Api {
    private final IStore store;
    public Api(IStore s) { store = s; }
    public Object handle(String body) { return store.load(body); }   // project reaches the sink here (line 6)
}
