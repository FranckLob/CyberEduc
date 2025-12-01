package com.franck.cybereduc.service;

import com.franck.cybereduc.model.DBUser;
import com.franck.cybereduc.model.Role;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class DBUserService {

    private final PasswordEncoder passwordEncoder;

    public DBUserService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // pour le password : on encode avant de sauvegarder...; pour le rôle on le force à USER
    public DBUser createDBUser(String username, String password) {
        return new DBUser (
            username,
            this.passwordEncoder.encode(password),
            Role.valueOf("ROLE_USER")
        );
    }

    // pour le password : on encode avant de sauvegarder...; pour le rôle on le force à ADMIN
    public DBUser createDBAdmin(String username, String password) {
        return new DBUser (
            username,
            this.passwordEncoder.encode(password),
            Role.valueOf("ROLE_ADMIN")
        );
    }
    
}
