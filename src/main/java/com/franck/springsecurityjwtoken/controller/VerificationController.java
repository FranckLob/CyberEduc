package com.franck.springsecurityjwtoken.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class VerificationController {

    @GetMapping(path = "/verification")
    public String verification() {
        return "VERIFICATION OK : a token is needed !!!";
    }

}
