package com.example.sync;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.XStream;
import java.io.IOException;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;
import javax.servlet.http.HttpServletRequest;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public class ImportService {

    private final XStream xstream = new XStream();
    private final ObjectMapper mapper = new ObjectMapper();

    public ImportService() {
        XStream.setupDefaultSecurity(xstream);
        xstream.allowTypes(new Class[] {Config.class, Entry.class});
    }

    public Object fromXml(String xml) {
        return xstream.fromXML(xml);
    }

    public Object fromYaml(String yaml) {
        Yaml parser = new Yaml(new SafeConstructor(new LoaderOptions()));
        return parser.load(yaml);
    }

    public Object fromJson(String json) throws IOException {
        return mapper.readValue(json, Config.class);
    }

    public Object fromJava(HttpServletRequest request) throws IOException {
        try (ValidatingObjectInputStream in = new ValidatingObjectInputStream(request.getInputStream())) {
            in.accept(Config.class, Entry.class);
            return in.readObject();
        } catch (ClassNotFoundException e) {
            throw new IOException(e);
        }
    }
}
