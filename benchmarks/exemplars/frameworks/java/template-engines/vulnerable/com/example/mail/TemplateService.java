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
        Velocity.evaluate(context, out, "preview", source);   // frame-expect: CWE-1336
        return out.toString();
    }

    public String freemarker(String source, String name) throws IOException {
        Map<String, Object> model = new HashMap<>();
        model.put("name", name);
        StringWriter out = new StringWriter();
        try {
            Template template = new Template("preview", new StringReader(source), freemarker);   // frame-expect: CWE-1336
            template.process(model, out);
        } catch (Exception e) {
            throw new IOException(e);
        }
        return out.toString();
    }

    public String thymeleaf(String source, String name) {
        Context context = new Context();
        context.setVariable("name", name);
        return thymeleaf.process(source, context);   // frame-expect: CWE-1336
    }

    public String groovy(String script) {
        Binding binding = new Binding();
        GroovyShell shell = new GroovyShell(binding);
        return String.valueOf(shell.evaluate(script));   // frame-expect: CWE-94
    }

    public Object mvel(String expression) {
        return MVEL.eval(expression, new HashMap<String, Object>());   // frame-expect: CWE-917
    }

    public Object jexl(String expression) {
        JexlExpression compiled = jexl.createExpression(expression);   // frame-expect: CWE-917
        return compiled.evaluate(new MapContext());
    }
}
