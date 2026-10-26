package com.example.ops;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

public class OpsService {

    private static final Path REPORTS = Paths.get("/var/reports");

    public String ping(String host) throws IOException {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);   // frame-expect: CWE-78
        return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    public String archive(String directory) throws IOException {
        ProcessBuilder builder = new ProcessBuilder("sh", "-c", "tar czf /tmp/out.tgz " + directory);   // frame-expect: CWE-78
        Process p = builder.start();
        return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    public String readReport(String name) throws IOException {
        Path file = REPORTS.resolve(name);
        return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);   // frame-expect: CWE-22
    }

    public String importXml(InputStream xml) throws IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(xml);   // frame-expect: CWE-611
            return doc.getDocumentElement().getTagName();
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public Object findResource(String jndiName) {
        try {
            return new InitialContext().lookup(jndiName);   // frame-expect: CWE-94
        } catch (NamingException e) {
            return null;
        }
    }
}
