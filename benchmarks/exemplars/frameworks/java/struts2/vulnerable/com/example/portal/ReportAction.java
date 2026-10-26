package com.example.portal;

import com.opensymphony.xwork2.ActionContext;
import com.opensymphony.xwork2.ActionSupport;
import com.opensymphony.xwork2.util.ValueStack;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Map;

public class ReportAction extends ActionSupport {

    private String fileName;
    private String expression;
    private InputStream inputStream;
    private Object computed;

    public String download() throws Exception {
        inputStream = new FileInputStream("/var/reports/" + fileName);   // frame-expect: CWE-22
        return SUCCESS;
    }

    public String fromParameters() throws Exception {
        Map<String, Object> params = ActionContext.getContext().getParameters();
        String[] names = (String[]) params.get("report");
        inputStream = new FileInputStream("/var/reports/" + names[0]);   // frame-expect: CWE-22
        return SUCCESS;
    }

    public String evaluate() {
        ValueStack stack = ActionContext.getContext().getValueStack();
        computed = stack.findValue(expression);   // frame-expect: CWE-917
        return SUCCESS;
    }

    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    public String getExpression() { return expression; }
    public void setExpression(String expression) { this.expression = expression; }
    public InputStream getInputStream() { return inputStream; }
    public Object getComputed() { return computed; }
}
