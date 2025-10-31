package com.example.auth_api.infra.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.auth_api.entity.Users;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

// Indica que essa classe é um "serviço" gerenciado pelo Spring.
// Isso significa que o Spring vai criar uma instância dela automaticamente
// e permitir que outras classes possam injetá-la com @Autowired.
@Service
public class TokenService {

    // Injeta o valor da chave secreta que está definida no arquivo application.properties
    // Exemplo: api.security.token.secret=meuSegredoSuperSeguro
    // Essa chave é usada para "assinar" e "verificar" o token JWT.
    @Value("${api.security.token.secret}")
    private String secret;


    // Esse metodo é responsável por gerar um novo token JWT para um usuário autenticado.
    // Ele será chamado depois que o login for validado com sucesso.
    public String generateToken(Users users) {
        try {
            // Cria o algoritmo de assinatura que será usado para gerar o token.
            // Aqui é usado o HMAC256, um algoritmo simétrico que usa a "secret" como chave.
            Algorithm algorithm = Algorithm.HMAC256(secret);

            // Cria o token JWT com as informações desejadas.
            // A biblioteca JWT do Java (Auth0) permite montar o token com várias informações.
            String token = JWT.create()
                    // withIssuer: define quem está emitindo o token (no caso, "auth-api").
                    // Serve como uma identificação da origem do token.
                    .withIssuer("auth-api")

                    // withSubject: define o "assunto" do token, normalmente o login do usuário.
                    // Isso é o que vai identificar quem é o dono do token.
                    .withSubject(users.getLogin())

                    // withExpiresAt: define a data e hora em que o token vai expirar.
                    // Isso evita que o token fique válido para sempre.
                    .withExpiresAt(generateExpiration())

                    // sign: assina o token com o algoritmo e a chave secreta definidos acima.
                    // Essa assinatura garante que ninguém consiga modificar o token sem saber a chave.
                    .sign(algorithm);

            // Retorna o token JWT pronto, já assinado.
            return token;

        } catch (JWTCreationException e) {
            // Caso aconteça algum erro na criação do token, lança uma exceção personalizada.
            // Isso ajuda a identificar falhas na geração (por exemplo, chave inválida ou erro de assinatura).
            throw new RuntimeException("Erro ao gerar token: ", e);
        }
    }


    // Esse metodo valida um token JWT recebido em uma requisição.
    // Ele é usado pelo filtro (SecurityFilter) para verificar se o token é válido e extrair o login.
    public String validateToken(String token) {
        try {
            // Cria o mesmo algoritmo usado na geração do token.
            // Isso é essencial para que a assinatura seja verificada corretamente.
            Algorithm algorithm = Algorithm.HMAC256(secret);

            // Usa o JWT.require() para montar o verificador do token.
            // Ele define as regras esperadas: mesmo algoritmo e mesmo "issuer" (auth-api).
            return JWT.require(algorithm)
                    .withIssuer("auth-api") // verifica se o token foi emitido pela nossa aplicação
                    .build()                // constrói o verificador
                    .verify(token)          // verifica a validade e assinatura do token
                    .getSubject();          // retorna o "subject" (login do usuário) contido no token

        } catch (JWTVerificationException e) {
            // Se a verificação falhar (token expirado, modificado ou inválido),
            // o metodo captura a exceção e retorna uma string vazia.
            // Isso indica que o token não é válido.
            return "";
        }
    }

    // --------------------------------------------------------------------
    // MÉTODO: generateExpiration
    // --------------------------------------------------------------------
    // Esse método gera a data e hora de expiração do token.
    // Aqui foi definido que o token expira em 2 horas a partir do momento da criação.
    private Instant generateExpiration() {
        // LocalDateTime.now() -> pega o horário atual do sistema.
        // plusHours(2) -> adiciona 2 horas (validade do token).
        // toInstant(ZoneOffset.of("-03:00")) -> converte para Instant considerando o fuso horário do Brasil.
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}