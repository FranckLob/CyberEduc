package com.franck.springsecurityjwtoken.filter;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.franck.springsecurityjwtoken.service.CustomUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.franck.springsecurityjwtoken.configuration.JwtUtils;

// chaque requête doit être filtrée par le jwt
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtils jwtUtils;

    public JwtFilter(CustomUserDetailsService customUserDetailsService, JwtUtils jwtUtils) {
        this.customUserDetailsService = customUserDetailsService;
        this.jwtUtils = jwtUtils;
    }

    @SuppressWarnings("null")
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // le token se trouve dans le header de la requête http
        final String authorization = request.getHeader("Authorization");

        String username = null;
        String jwt = null;

        // il s'agit d'un bearer token
        if (authorization != null && authorization.startsWith("Bearer ")) {
            // la chaine "Bearer " fait 7 caractères, d'où le substring...
            jwt = authorization.substring(7);
            username = jwtUtils.getUsernameFromToken(jwt);
        }

        // on vérifie que l'utilisateur n'est pas encore authentifié
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
            // on récupère userDetails pour regarder la validité du token
            if (jwtUtils.isValidToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, userDetails.getAuthorities());
                // le setDetails ci-dessous permet de récupérer des infos d'authent supplémentaires
                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // le token est valide, on considère que l'utilisateur est authentifié
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        // pour appeler le filtre suivant
        filterChain.doFilter(request, response);
    }

}