package com.franck.springsecurityjwtoken.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.franck.springsecurityjwtoken.model.DBUser;
import com.franck.springsecurityjwtoken.repository.DBUserRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService{

    private final DBUserRepository dbUserRepository;

    public CustomUserDetailsService(DBUserRepository dbUserRepository) {
        this.dbUserRepository = dbUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        DBUser dbUser = dbUserRepository.findDbUserByUsername(username);
        if (dbUser == null) {
            throw new UsernameNotFoundException("DBUser not found : " + username);
        }
        // le user de spring security ici
        return new User(dbUser.getUsername(), dbUser.getPassword(), java.util.Collections.singletonList(new SimpleGrantedAuthority(dbUser.getRole().toString())));
    }

}
