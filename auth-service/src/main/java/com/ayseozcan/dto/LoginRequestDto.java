package com.ayseozcan.dto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;

@Getter
public class LoginRequestDto {

    @NotEmpty(message = "Username field cannot be empty")
    private String username;

    @NotEmpty(message = "Password field cannot be empty")
    private String password;
}
