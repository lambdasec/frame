package app;

import java.io.IOException;
import java.util.Set;
import org.springframework.web.bind.annotation.*;

@RestController
public class Api {
    private static final Set<String> ALLOWED = Set.of("example.com", "example.org");

    @GetMapping("/ping")
    public String ping(@RequestParam("host") String host) throws IOException {
        if (!ALLOWED.contains(host)) {
            return "unknown host";                        // fixed: attacker data never reaches the command
        }
        Runtime.getRuntime().exec("ping -c 1 " + host);
        return "started";
    }
}
