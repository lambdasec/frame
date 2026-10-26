package com.example.faces;

import java.io.IOException;
import java.io.Serializable;
import java.util.List;
import java.util.Map;
import javax.enterprise.context.RequestScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;

@Named("catalog")
@RequestScoped
public class CatalogBean implements Serializable {

    @Inject
    private ItemRepository repository;

    private String term;
    private String returnUrl;
    private List<Item> items;

    public String search() {
        items = repository.findByTerm(term);
        return "results";
    }

    public String show() {
        FacesContext context = FacesContext.getCurrentInstance();
        Map<String, String> params = context.getExternalContext().getRequestParameterMap();
        String id = params.get("id");
        items = repository.findById(id);
        return "detail";
    }

    public void back() throws IOException {
        ExternalContext external = FacesContext.getCurrentInstance().getExternalContext();
        external.redirect(returnUrl);   // frame-expect: CWE-601
    }

    public void banner() throws IOException {
        FacesContext context = FacesContext.getCurrentInstance();
        context.getExternalContext().getResponseOutputWriter().write("<b>" + term + "</b>");   // frame-expect: CWE-79
    }

    public Object evaluate() {
        FacesContext context = FacesContext.getCurrentInstance();
        String expression = context.getExternalContext().getRequestParameterMap().get("expr");
        return context.getApplication().evaluateExpressionGet(context, "#{" + expression + "}", Object.class);   // frame-expect: CWE-917
    }

    public String getTerm() { return term; }
    public void setTerm(String term) { this.term = term; }
    public String getReturnUrl() { return returnUrl; }
    public void setReturnUrl(String returnUrl) { this.returnUrl = returnUrl; }
    public List<Item> getItems() { return items; }
}
