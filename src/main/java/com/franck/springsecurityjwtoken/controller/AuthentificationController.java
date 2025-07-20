package com.franck.springsecurityjwtoken.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.franck.springsecurityjwtoken.configuration.JwtUtils;
import com.franck.springsecurityjwtoken.model.DBUser;
import com.franck.springsecurityjwtoken.repository.DBUserRepository;

@RestController
@RequestMapping("/api/auth")
public class AuthentificationController {

    private final DBUserRepository dbUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    public AuthentificationController(DBUserRepository dbUserRepository, PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager, JwtUtils jwtUtils) {
        this.dbUserRepository = dbUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping(path = "/register", consumes = "application/json", produces = "application/json")
    @Transactional
    public ResponseEntity<?> register(@RequestBody DBUser dbuser) {
        if (dbUserRepository.findDbUserByUsername(dbuser.getUsername()) != null) {
            return ResponseEntity.badRequest().body("Username is still known");
        }
        // pour le password : on encode avant de sauvegarder...; pour le rôle pn prend tel quel, rien à faire
        dbuser.setPassword(passwordEncoder.encode(dbuser.getPassword()));
        // on peut désormais sauvegarder
        return ResponseEntity.ok(dbUserRepository.save(dbuser));
    }

    @PostMapping(path = "/login", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> login(@RequestBody DBUser dbUser) {
        try {
            // on essaie d'authentifier l'utilisateur; UsernamePasswordAuthenticationToken
            // utilise le username et le password du Principal reçu du serveur
            // l'objet de type Authentication nous permet de savoir si le user est
            // authentifié ou non
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(dbUser.getUsername(), dbUser.getPassword()));
            // si le user qui s'est signé est authentifié, alors on peut créer un token de
            // type Bearer associé
            if (authentication.isAuthenticated()) {
                Map<String, Object> authData = new HashMap<>();
                authData.put("token", jwtUtils.generateToken(dbUser.getUsername()));
                authData.put("type", "Bearer ");
                return ResponseEntity.ok(authData);
            } else {
                return ResponseEntity.badRequest().body("Invalid username or password");
            }

        } catch (AuthenticationException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // Avant création du user :
    // {
    //     "username":"franck",
    //     "password":"password123",
    //     "role":"USER"
    // }
    //
    // Après register, création du user : franck; password123, USER
    // {
    //     "id": 3,
    //     "username": "franck",
    //     "password": "$2a$10$0TH0HLsN3M5ZE0s1DkxKPOAyQ63hdu9N0P3sQLfe6IEWxRUsa8BGm",
    //     "role": "USER"
    // }
    // Après login :
    // {
    //     "type": "Bearer ",
    //     "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmcmFuY2syIiwiaWF0IjoxNzI5OTM2Nzg1LCJleHAiOjE3Mjk5Mzc2ODV9.miShEdXJ4Ha1y-bqZh5kbSIyuGFVEtf-gj9GytNuNaY"
    // }

}
