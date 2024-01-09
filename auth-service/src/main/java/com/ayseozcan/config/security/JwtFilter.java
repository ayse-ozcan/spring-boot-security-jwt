package com.ayseozcan.config.security;

import com.ayseozcan.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final JwtUserDetails jwtUserDetails;

    public JwtFilter(JwtService jwtService, JwtUserDetails jwtUserDetails) {
        this.jwtService = jwtService;
        this.jwtUserDetails = jwtUserDetails;
    }

    //It is necessary to check whether there is token information in the incoming request.
    //If the user has already been authenticated previously,
    //we return the incoming request as is without any additional processing to avoid performing extra steps in this case.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeaderParameters = request.getHeader("Authorization");
        if (authHeaderParameters != null && authHeaderParameters.startsWith("Bearer ")
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String token = authHeaderParameters.substring(7);
            Optional<Long> authId = jwtService.getIdFromToken(token);
            if (authId.isPresent()) {
                UserDetails userDetails = jwtUserDetails.getUserByAuthId(authId.get());
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                try {
                    throw new Exception("Token create error");
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
