package com.example.auth_api.service;

import com.example.auth_api.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//Essa anotação @Service, serve para o spring identificar que aqui é aonde fica o service da nossa aplicação
//E não resulte erros na hora de compilar o projeto
@Service
public class AuthorizacionService implements UserDetailsService {
    //@Autowired é uma anotação que serve para informar ao SpringBoot que estamos
    //realizando uma injeção de depêndencia
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return this.userRepository.findByLogin(username);
    }
}
