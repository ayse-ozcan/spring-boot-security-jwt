package com.ayseozcan.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
public class JwtService {

    @Value("${security.oauth2.jwt.secret-key}")
    private String secretKey;

    //The id information of the logged-in user to generate a new token for them.
    //The information you embed in the claims object is openly readable.
    //!!For example -- the email, password... should not be placed within the claims.
    public Optional<String> createToken(Long id) {
        String token;
        Long expireDate = 1000L * 60 * 5;
        try {
            Date issuedAt = new Date();
            Date expiresAt = new Date(System.currentTimeMillis() + expireDate);
            token = JWT.create()
                    .withClaim("id", id)
                    .withIssuer("test")
                    .withIssuedAt(issuedAt)
                    .withExpiresAt(expiresAt)
                    .sign(Algorithm.HMAC512(secretKey));
            return Optional.of(token);
        } catch (Exception exception) {
            return Optional.empty();
        }
    }

    //We use it to verify the accuracy of the token.
    //Token validity is checked.
    //The id information is retrieved from the token's payload.
    public Optional<Long> getIdFromToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC512(secretKey);
            JWTVerifier jwtVerifier = JWT.require(algorithm)
                    .withIssuer("test")
                    .build();
            DecodedJWT decodedJWT = jwtVerifier.verify(token);
            Date expiresAt = decodedJWT.getExpiresAt();
            if (expiresAt != null && expiresAt.after(new Date())) {
                return Optional.of(decodedJWT.getClaim("id").asLong());
            } else {
                return Optional.empty();
            }
        } catch (Exception exception) {
            return Optional.empty();
        }
    }
}