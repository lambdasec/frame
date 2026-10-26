package com.example.shop;

import java.net.URI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class PageController {

    @Autowired
    private ProductService service;

    @Autowired
    private StorageService storage;

    @GetMapping("/login-done")
    public String loginDone(@RequestParam("returnTo") String returnTo) {
        return "redirect:" + returnTo;   // frame-expect: CWE-601
    }

    @GetMapping("/moved")
    public ResponseEntity<Void> moved(@RequestParam String target) {
        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(target));   // frame-expect: CWE-601
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @GetMapping("/doc/{section}")
    public String doc(@PathVariable String section, Model model) {
        model.addAttribute("title", "Documentation");
        return "doc/index :: " + section;   // frame-expect: CWE-1336
    }

    @PostMapping("/search")
    public String search(@ModelAttribute SearchForm form, Model model) {
        model.addAttribute("results", service.search(form.getName(), "asc"));
        return "results";
    }

    @PostMapping("/upload")
    public String upload(@RequestParam("file") MultipartFile file) throws Exception {
        storage.save(file.getOriginalFilename(), file.getBytes());
        return "redirect:/done";
    }
}
