package com.ayseozcan.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

@Getter
public class RegisterRequestDto {

    @NotEmpty(message = "Name field cannot be empty")
    @Size(min = 3, max = 20, message = "Name must be between 3 and 20 characters.")
    private String name;

    @NotEmpty(message = "Surname field cannot be empty")
    @Size(min = 3, max = 20, message = "Surname must be between 3 and 20 characters.")
    private String surname;

    @NotEmpty(message = "Username field cannot be empty")
    @Size(min = 3, max = 20, message = "Username must be between 3 and 20 characters.")
    private String username;

    @NotEmpty(message = "Email field cannot be empty")
    @Email(message = "Please enter a valid email address")
    @Pattern(regexp = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$")
    private String email;

    @NotEmpty(message = "Password field cannot be empty")
    @Pattern(message = "4 to 8 character password requiring numbers and both lowercase and uppercase letters",
            regexp = "^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{4,8}$")
    private String password;

}
