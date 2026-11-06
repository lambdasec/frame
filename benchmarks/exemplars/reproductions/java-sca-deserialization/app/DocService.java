package app;
import com.acme.UnsafeXml;
public class DocService {
    public Object load(String raw) {
        return new UnsafeXml().parse(raw);   // project reaches the vulnerable function here
    }
}
