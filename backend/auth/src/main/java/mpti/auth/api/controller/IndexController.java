package mpti.auth.api.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class IndexController {
    @GetMapping("")
    public String checkDuplicateId() {
        return "<h1>Hello Auth Server Main Page</h1>";
    }
}
