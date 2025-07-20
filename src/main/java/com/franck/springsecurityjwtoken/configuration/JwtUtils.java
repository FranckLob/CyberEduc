package com.franck.springsecurityjwtoken.configuration;

import java.util.Date;
import java.util.Map;
import java.util.function.Function;
import java.util.HashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class JwtUtils {

    private String secretKey = "9a4f2c8d3b7a1e6f45c8a0b3f267d8b1d4e6f3c8a9d2b5f8e3a9c8b5f6v8a3d9";

    @Value("${app.expiration-time}")
    private long expirationTime;

    //--------------- génération et création du token ---------------

    // génération et création du token (qui est d'ailleurs au format String)
     public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
            return createToken(claims, username);
    }

    // Building JWTs With JJWT
    private String createToken(Map<String, Object> ourClaims, String username) {
        return Jwts.builder()
        .claims(ourClaims)
        .subject(username)
        .issuedAt(new Date(System.currentTimeMillis()))
        .expiration(new Date(System.currentTimeMillis() + expirationTime))
        .signWith(getSignKey())
        .compact();  
    }

    // cryptographic signing of the JWT (making it a JWS)
    private javax.crypto.SecretKey getSignKey() {
        //return new SecretKeySpec(secretKey.getBytes(), "HS256");
        //return Jwts.SIG.HS256.key().build();
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //--------------- validation du token ---------------

    // validation du token reçu : username issu du token ok et token non expiré
    public boolean isValidToken(String token, UserDetails userDetails) {
        String usernameFromToken = getUsernameFromToken(token);
        return usernameFromToken.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    public String getUsernameFromToken(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    private boolean isTokenExpired(String token) {
        return getExpirationDate(token).before(new Date());
    }

    private Date getExpirationDate(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // même clé pour décrypter que pour crypter
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
        .verifyWith(getSignKey())
        .build()
        .parseSignedClaims(token)
        .getPayload();
    }

}
