package com.franck.cybereduc.service;

import com.franck.cybereduc.model.DBUser;
import com.franck.cybereduc.model.Role;
import com.franck.cybereduc.repository.DBUserRepository;

import java.util.List;
import java.util.Optional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DBUserService {

    private final DBUserRepository dbUserRepository;

    private final PasswordEncoder passwordEncoder;

    public DBUserService(DBUserRepository dbUserRepository, PasswordEncoder passwordEncoder) {
        this.dbUserRepository = dbUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // pour le password : on encode avant de sauvegarder...; pour le rôle on le force à USER
    @Transactional
    public DBUser createDBUser(String username, String password) {
        DBUser user =  new DBUser (
            username,
            this.passwordEncoder.encode(password),
            Role.valueOf("ROLE_USER")
        );
        return dbUserRepository.save(user);
    }

    // pour le password : on encode avant de sauvegarder...; pour le rôle on le force à ADMIN
    @Transactional
    public DBUser createDBAdmin(String username, String password) {
        return new DBUser (
            username,
            this.passwordEncoder.encode(password),
            Role.valueOf("ROLE_ADMIN")
        );
    }

    public Optional<DBUser> getUserByUsername(String username) {
        return dbUserRepository.findDbUserByUsername(username);
    }

    public List<DBUser> getAllUsers() {
        return dbUserRepository.findAll();
    }

    public long countNumberOfUsersByRole(Role role) {
        return dbUserRepository.countByRole(role);
    }
    
}
