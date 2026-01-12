package com.example.spring_security_jwt_auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {

    private final String SECRET_KEY = "9TKUB+9XNGAGJPWC8k/Fu+0BxLFZxy2SMPARAlnCjdw=";

    public String extractUserName(String jwt) {
        return  "";
    }

    public String generateToken(UserDetails userDetails) {
        return  generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(
        Map<String, Object> extraClaims,
        UserDetails userDetails
    ) {
        return  Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24 ))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }


    public  boolean isTokenValid(String token,UserDetails userDetails) {
        final  String username = extractUserName(token);
        return  (username.equals(userDetails.getUsername())) &&
        !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        final Date expirationDate = extractClaim(token,Claims::getExpiration);
        return  expirationDate.before(new Date());
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)         // parse JWS token
                .getBody();                    // get Claims
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
