package com.example.mail;

import freemarker.template.Configuration;
import freemarker.template.Template;
import groovy.lang.Binding;
import groovy.lang.GroovyShell;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.jexl3.JexlEngine;
import org.apache.commons.jexl3.JexlExpression;
import org.apache.commons.jexl3.MapContext;
import org.apache.commons.jexl3.JexlBuilder;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.mvel2.MVEL;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

public class TemplateService {

    private final Configuration freemarker = new Configuration(Configuration.VERSION_2_3_31);
    private final TemplateEngine thymeleaf = new TemplateEngine();
    private final JexlEngine jexl = new JexlBuilder().create();

    public String velocity(String source, String name) {
        VelocityContext context = new VelocityContext();
        context.put("name", name);
        StringWriter out = new StringWriter();
        Velocity.evaluate(context, out, "preview", "Hello $name, your preview is ready");
        return out.toString();
    }

    public String freemarker(String source, String name) throws IOException {
        Map<String, Object> model = new HashMap<>();
        model.put("name", name);
        StringWriter out = new StringWriter();
        try {
            Template template = freemarker.getTemplate("preview.ftl");
            template.process(model, out);
        } catch (Exception e) {
            throw new IOException(e);
        }
        return out.toString();
    }

    public String thymeleaf(String source, String name) {
        Context context = new Context();
        context.setVariable("name", name);
        return thymeleaf.process("mail/preview", context);
    }

    public String groovy(String script) {
        Binding binding = new Binding();
        GroovyShell shell = new GroovyShell(binding);
        return String.valueOf(shell.evaluate("name.toUpperCase()"));
    }

    public Object mvel(String expression) {
        return MVEL.eval("1 + 1", new HashMap<String, Object>());
    }

    public Object jexl(String expression) {
        JexlExpression compiled = jexl.createExpression("name");
        return compiled.evaluate(new MapContext());
    }
}
