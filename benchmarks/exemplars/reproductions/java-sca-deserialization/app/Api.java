package app;
public class Api {                           // entry point
    public Object handle(String body) { return new DocService().load(body); }
}
