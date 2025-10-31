package com.example.auth_api.infra.security;

import com.example.auth_api.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Essa anotação indica que o Spring deve gerenciar automaticamente essa classe como um componente.
// Assim, o Spring consegue injetar (autowire) essa classe onde for necessário.
@Component
public class SecurityFilter extends OncePerRequestFilter {

    // Injeta o serviço que sabe lidar com tokens JWT.
    // Esse TokenService é responsável por gerar e validar tokens.
    @Autowired
    private TokenService tokenService;

    // Injeta o repositório de usuários, usado para buscar o usuário no banco
    // com base nas informações contidas no token.
    @Autowired
    private UserRepository userRepository;

    /*
        Esse é o metodo principal do filtro.
        Ele é chamado automaticamente toda vez que uma requisição chega na sua API.
        Aqui é onde você intercepta a requisição para verificar se existe um token JWT válido.

    */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Primeiro, tenta recuperar o token JWT do cabeçalho da requisição HTTP.
        var token = this.recoverToken(request);
        if(token != null){
            // Se o token existir, pedimos ao TokenService para validá-lo.
            // O metodo validateToken(token) normalmente devolve o login do usuário
            // (que foi gravado dentro do token quando ele foi gerado).
            var login = tokenService.validateToken(token);
            UserDetails user = this.userRepository.findByLogin(login);

            // Cria um objeto de autenticação com o usuário encontrado.
            // O primeiro parâmetro é o usuário autenticado.
            // O segundo (null) seria a senha, mas não precisamos dela aqui.
            // O terceiro são as "autoridades" (roles/permissões) do usuário.
            var authentication = new UsernamePasswordAuthenticationToken(user, null,user.getAuthorities());

            // Define a autenticação no contexto de segurança do Spring.
            // A partir desse ponto, o Spring sabe que essa requisição
            // está sendo feita por um usuário autenticado.
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // Continua o fluxo normal da requisição.
        // Mesmo depois de passar pelo filtro, a requisição segue adiante
        // para o próximo filtro ou para o controller que ela deveria atingir.
        filterChain.doFilter(request,response);
    }
    // Esse metodo tenta recuperar o token do cabeçalho "Authorization" da requisição HTTP.
    private String recoverToken(HttpServletRequest resquest){
        var authHeader = resquest.getHeader("Authorization");
        if(authHeader == null){
            return null;
        }
        else{
            // Se houver, remove a palavra "Bearer " do começo e retorna só o token JWT.
            return authHeader.replace("Bearer ", "");
        }
    }
}
