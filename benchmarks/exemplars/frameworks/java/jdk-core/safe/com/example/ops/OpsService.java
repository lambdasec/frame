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
        Process p = Runtime.getRuntime().exec(new String[] {"ping", "-c", "1", "primary".equals(host) ? "10.0.0.1" : "10.0.0.2"});
        return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    public String archive(String directory) throws IOException {
        ProcessBuilder builder = new ProcessBuilder("tar", "czf", "/tmp/out.tgz", "-C", "/srv/data", "--", "reports".equals(directory) ? "reports" : "exports");
        Process p = builder.start();
        return new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    public String readReport(String name) throws IOException {
        Path file = REPORTS.resolve(new java.io.File(name).getName());
        return new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    }

    public String importXml(InputStream xml) throws IOException {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setXIncludeAware(false);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(xml);
            return doc.getDocumentElement().getTagName();
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public Object findResource(String jndiName) {
        try {
            return new InitialContext().lookup("java:comp/env/" + ("mail".equals(jndiName) ? "mail/Session" : "jdbc/ds"));
        } catch (NamingException e) {
            return null;
        }
    }
}
