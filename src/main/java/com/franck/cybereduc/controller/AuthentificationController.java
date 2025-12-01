package com.franck.cybereduc.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.franck.cybereduc.configuration.JwtUtils;
import com.franck.cybereduc.dto.UserDto;
import com.franck.cybereduc.model.DBUser;
import com.franck.cybereduc.model.Role;
import com.franck.cybereduc.repository.DBUserRepository;
import com.franck.cybereduc.service.DBUserService;

import io.swagger.v3.oas.annotations.Hidden;

@RestController
@RequestMapping("/api/auth")
public class AuthentificationController {

    private static final String creationImpossible = "Création impossible";

    private final DBUserRepository dbUserRepository;
    private final DBUserService dbUserService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    public AuthentificationController(DBUserRepository dbUserRepository, DBUserService dbUserService,
            AuthenticationManager authenticationManager, JwtUtils jwtUtils) {
        this.dbUserRepository = dbUserRepository;
        this.dbUserService = dbUserService;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping(path = "/register", consumes = "application/json", produces = "application/json")
    @Transactional
    public ResponseEntity<?> register(@RequestBody UserDto userDto) {
        if (dbUserRepository.findDbUserByUsername(userDto.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body(creationImpossible);
        }
        DBUser user = this.dbUserService.createDBUser(userDto.getUsername(), userDto.getPassword());
        // on peut désormais sauvegarder
        dbUserRepository.save(user);
        return ResponseEntity.ok(String.join(" ", "user", "\"", user.getUsername(), "\"", "créé !"));
    }

    @Hidden
    @PostMapping(path = "/register/admin", consumes = "application/json", produces = "application/json")
    @Transactional
    public ResponseEntity<?> registerAdmin(@RequestBody UserDto userDto) {
        if (dbUserRepository.findDbUserByUsername(userDto.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body(creationImpossible);
        }
        // seulement deux admins
        if (dbUserRepository.countByRole(Role.valueOf("ROLE_ADMIN")) > 2) {
             return ResponseEntity.badRequest().body(creationImpossible);
        }
        DBUser user = this.dbUserService.createDBAdmin(userDto.getUsername(), userDto.getPassword());
        dbUserRepository.save(user);
        return ResponseEntity.ok(String.join(" ", "user", "\"", user.getUsername(), "\"", "créé !"));
    }

    @PostMapping(path = "/login", consumes = "application/json", produces = "application/json")
    public ResponseEntity<?> login(@RequestBody UserDto userDto) {
        try {
            // on essaie d'authentifier l'utilisateur; UsernamePasswordAuthenticationToken
            // utilise le username et le password du Principal reçu du serveur
            // l'objet de type Authentication nous permet de savoir si le user est
            // authentifié ou non
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(userDto.getUsername(), userDto.getPassword()));
            // si le user qui s'est signé est authentifié, alors on peut créer un token de
            // type Bearer associé
            if (authentication.isAuthenticated()) {
                Map<String, Object> authData = new HashMap<>();
                authData.put("token", jwtUtils.generateToken(userDto.getUsername()));
                authData.put("type", "Bearer ");
                return ResponseEntity.ok(authData);
            } else {
                return ResponseEntity.badRequest().body("Invalid username or password");
            }

        } catch (AuthenticationException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

}
