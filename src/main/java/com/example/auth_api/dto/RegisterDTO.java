package com.example.auth_api.dto;

import com.example.auth_api.enums.UserRoles;

public record RegisterDTO(String username, String password, UserRoles role) {}