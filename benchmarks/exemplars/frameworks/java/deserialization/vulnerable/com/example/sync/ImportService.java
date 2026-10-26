package com.example.sync;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thoughtworks.xstream.XStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;
import org.yaml.snakeyaml.Yaml;

public class ImportService {

    private final XStream xstream = new XStream();
    private final ObjectMapper mapper = new ObjectMapper().enableDefaultTyping();

    public Object fromXml(String xml) {
        return xstream.fromXML(xml);   // frame-expect: CWE-502
    }

    public Object fromYaml(String yaml) {
        Yaml parser = new Yaml();
        return parser.load(yaml);   // frame-expect: CWE-502
    }

    public Object fromJson(String json) throws IOException {
        return mapper.readValue(json, Object.class);   // frame-expect: CWE-502
    }

    public Object fromJava(HttpServletRequest request) throws IOException {
        try (ObjectInputStream in = new ObjectInputStream(request.getInputStream())) {   // frame-expect: CWE-502
            return in.readObject();
        } catch (ClassNotFoundException e) {
            throw new IOException(e);
        }
    }
}
