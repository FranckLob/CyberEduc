package com.franck.cybereduc.controller;

import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.franck.cybereduc.model.DBUser;
import com.franck.cybereduc.model.Role;
import com.franck.cybereduc.service.DBUserService;

@RestController
@RequestMapping("/api")
public class VerificationController {

    private final DBUserService dbUserService;

    public VerificationController(DBUserService dbUserService) {
        this.dbUserService = dbUserService;
    }
    
    @GetMapping(path = "/verification")
    public String verification() {
        return "VERIFICATION OK : a token is needed !!!";
    }

    @GetMapping(path = "/users")
    public String getUsers() {
        return dbUserService.getAllUsers()
            .stream()
            .filter(user -> user.getRole() == Role.ROLE_USER)
            .map(DBUser::getUsername)
            .collect(Collectors.joining(", "))
        ;
    }

    @GetMapping(path = "/admin/users")
    public String getAdmins() {
        return dbUserService.getAllUsers()
            .stream()
            .filter(user -> user.getRole() == Role.ROLE_ADMIN)
            .map(DBUser::getUsername)
            .collect(Collectors.joining(", "))
        ;
    }

}
