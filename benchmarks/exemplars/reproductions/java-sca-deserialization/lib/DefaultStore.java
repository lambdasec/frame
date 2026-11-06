package lib;
import java.io.*;
public class DefaultStore implements IStore {
    public Object load(String data) {               // CWE-502: unsafe deserialization
        try (ObjectInputStream in =
                 new ObjectInputStream(new ByteArrayInputStream(data.getBytes()))) {
            return in.readObject();
        } catch (Exception e) { return null; }
    }
}
