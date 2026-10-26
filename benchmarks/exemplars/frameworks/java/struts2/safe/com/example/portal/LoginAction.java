package com.example.portal;

import com.opensymphony.xwork2.ActionSupport;
import java.io.IOException;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.struts2.ServletActionContext;

public class LoginAction extends ActionSupport {

    private String username;
    private String returnUrl;
    private String greeting;

    public String execute() throws IOException {
        if ("admin".equals(username)) {
            ServletActionContext.getResponse().sendRedirect("/portal/home");
            return NONE;
        }
        ServletActionContext.getResponse().getWriter().write("<p>Welcome " + StringEscapeUtils.escapeHtml4(this.username) + "</p>");
        return NONE;
    }

    public String preview() {
        String id = ServletActionContext.getRequest().getParameter("id");
        Product p = new ProductDao().byId(id);
        return p == null ? ERROR : SUCCESS;
    }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getReturnUrl() { return returnUrl; }
    public void setReturnUrl(String returnUrl) { this.returnUrl = returnUrl; }
    public String getGreeting() { return greeting; }
    public void setGreeting(String greeting) { this.greeting = greeting; }
}
