package app;

import org.springframework.web.bind.annotation.*;
import org.yaml.snakeyaml.Yaml;

@RestController
public class Config {
    @GetMapping("/config")
    public Object parse(@RequestParam("body") String body) {
        Yaml yaml = new Yaml();
        return yaml.load(body);      // CWE-502: the request body reaches Yaml.load
    }
}
