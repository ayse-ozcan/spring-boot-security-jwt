package com.ayseozcan.service;

import com.ayseozcan.dto.LoginRequestDto;
import com.ayseozcan.dto.RegisterRequestDto;
import com.ayseozcan.repository.IAuthRepository;
import com.ayseozcan.repository.entity.Auth;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AuthService {
    private final IAuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthService(IAuthRepository authRepository, PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.authRepository = authRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public Optional<Auth> findById(Long authId) {
        return authRepository.findById(authId);
    }

    public Boolean register(RegisterRequestDto dto) {

        if (authRepository.findOptionalByUsername(dto.getUsername()).isPresent()) {
            throw new RuntimeException("User already exist");
        }
        authRepository.save(Auth.builder().name(dto.getName())
                .surname(dto.getSurname())
                .username(dto.getUsername())
                .email(dto.getEmail())
                .password(passwordEncoder.encode(dto.getPassword()))
                .build());
        return true;
    }

    public String login(LoginRequestDto dto) {
        Optional<Auth> auth = authRepository.findOptionalByUsername(dto.getUsername());
        if (auth.isEmpty()) {
            throw new RuntimeException("User not found");
        }
        if (!passwordEncoder.matches(dto.getPassword(), auth.get().getPassword()) || !(dto.getUsername()).equals(auth.get().getUsername())) {
            throw new RuntimeException("Incorrect password or username");
        }
        return jwtService.createToken(auth.get().getId())
                .orElseThrow(() -> {
                    throw new RuntimeException("Token not created");
                });
    }

    public List<Auth> findAll() {
        List<Auth> users = authRepository.findAll();
        return users;
    }
}
