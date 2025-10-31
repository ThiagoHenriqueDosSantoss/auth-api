package com.example.auth_api.controllers;

import com.example.auth_api.dto.RegisterDTO;
import com.example.auth_api.entity.Users;
import com.example.auth_api.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @PostMapping("/registers")
    public ResponseEntity<Users> registerUser(@RequestBody RegisterDTO data){
        Users response = this.userService.register(data);
        return ResponseEntity.ok(response);
    }
    @GetMapping
    public ResponseEntity<List<Users>> getUsers(){
        List<Users> response = this.userService.getUsers();
        return ResponseEntity.ok(response);
    }
}
