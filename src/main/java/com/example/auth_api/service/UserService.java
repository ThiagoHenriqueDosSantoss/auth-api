package com.example.auth_api.service;

import com.example.auth_api.dto.RegisterDTO;
import com.example.auth_api.entity.Users;
import com.example.auth_api.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public Users register(RegisterDTO data){
        Users u = new Users();
        u.setLogin(data.username());
        String encyptedPassword = new BCryptPasswordEncoder().encode(data.password());
        u.setPassword(encyptedPassword);
        u.setRole(data.role());

        return userRepository.save(u);
    }
    public List<Users> getUsers(){
        return this.userRepository.findAll();
    }
}
