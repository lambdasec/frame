package app;

import java.io.IOException;
import org.springframework.web.bind.annotation.*;

@RestController
public class Api {
    @GetMapping("/ping")
    public String ping(@RequestParam("host") String host) throws IOException {
        Runtime.getRuntime().exec("ping -c 1 " + host);   // CWE-78: the request's host reaches a command
        return "started";
    }
}
