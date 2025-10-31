package com.example.auth_api.controllers;

import com.example.auth_api.dto.AuthenticationDTO;
import com.example.auth_api.dto.LoginResponseDTO;
import com.example.auth_api.entity.Users;
import com.example.auth_api.infra.security.TokenService;
import com.example.auth_api.service.AuthorizacionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/auth")
public class AuthenticationController {
    // Injeta automaticamente o AuthenticationManager do Spring Security
    // Ele é o responsável por verificar se o login e a senha do usuário estão corretos.
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenService tokenService;

    // Define um endpoint (rota) HTTP do tipo POST em /login
    // Ou seja, quando alguém enviar uma requisição POST para /login, esse método será executado.
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody AuthenticationDTO data) {
        // Cria um objeto UsernamePasswordAuthenticationToken com o login e a senha recebidos.
        // Esse objeto é o formato padrão que o Spring usa para tentar autenticar um usuário.
        var usernamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password());

        // Aqui o AuthenticationManager tenta autenticar o usuário com base nos dados fornecidos.
        // Ele vai verificar se o login existe e se a senha está correta.
        // Se estiver tudo certo, o "auth" conterá as informações do usuário autenticado.
        var auth = authenticationManager.authenticate(usernamePassword);

        var token = this.tokenService.generateToken((Users) auth.getPrincipal());
        // Retorna uma resposta HTTP 200 (OK) se a autenticação foi bem-sucedida.
        // Aqui está devolvendo o token jwt
        return ResponseEntity.ok(new LoginResponseDTO(token));
    }
}
