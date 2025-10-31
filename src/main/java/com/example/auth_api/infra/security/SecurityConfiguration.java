package com.example.auth_api.infra.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.graphql.GraphQlProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

//@Configuration informa para o spring security que é uma classe de configuração
@Configuration
//@EnableWebSecurity diz para o Spring security habilitar a configuração de segurança web
//Porém nós vamos configurar da nossa maneira
@EnableWebSecurity
public class SecurityConfiguration {
    @Autowired
    private SecurityFilter securityFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // Esse metodo configura a segurança da aplicação.
        // Ele define como o Spring Security vai proteger as requisições HTTP (as chamadas à API).

        return httpSecurity
                // Desativa o CSRF (Cross-Site Request Forgery)
                // Essa proteção é importante em sites com formulários,
                // mas para APIs REST (que normalmente usam tokens como JWT), não é necessária.
                .csrf(csrf -> csrf.disable())

                // Define a política de gerenciamento de sessão como STATELESS
                // Isso significa que o servidor NÃO vai guardar informações de sessão do usuário.
                // Cada requisição precisa conter todas as informações de autenticação (por exemplo, o token JWT).
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, "/api/users").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/users/registers").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                        // Define as regras de autorização (quem pode acessar o quê)

                        // Diz que requisições HTTP do tipo POST para QUALQUER caminho (/*)
                        // só podem ser feitas por usuários que tenham o papel (role) "ADMIN".
                        // Exemplo: se tentar fazer um POST para /usuarios ou /produtos,
                        // apenas quem for ADMIN poderá.
                        .requestMatchers(HttpMethod.POST, "/*").hasRole("ADMIN")

                        // Qualquer outra requisição (GET, PUT, DELETE etc.) que não caia na regra acima
                        // precisa estar autenticada (ou seja, o usuário deve estar logado e ter um token válido).
                        .anyRequest().authenticated()
                )
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
                // Finaliza a configuração e "constrói" o filtro de segurança.
                // O Spring Security vai usar esse filtro para analisar todas as requisições HTTP.
                .build();
    }
    // Indica que esse metodo cria um "bean" gerenciado pelo Spring.
    // Isso significa que o Spring vai criar e disponibilizar esse objeto automaticamente
    // para ser usado em outras partes do código (como no seu controller de login, por exemplo).
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration
    ) throws Exception {
        // O AuthenticationConfiguration é um objeto que o Spring Security fornece.
        // Ele já sabe como montar o AuthenticationManager com base nas configurações
        // de autenticação da sua aplicação (como o UserDetailsService e o PasswordEncoder).

        // Aqui, simplesmente pedimos para ele nos devolver (get) o AuthenticationManager
        // configurado pelo próprio Spring.
        return authenticationConfiguration.getAuthenticationManager();
    }

    // Esse metodo cria e devolve um objeto que sabe "codificar" (criptografar) senhas.
    // A anotação @Bean normalmente é usada aqui (provavelmente está faltando no seu exemplo)
    // para que o Spring possa gerenciar esse PasswordEncoder e disponibilizá-lo em toda a aplicação.
    @Bean
    public PasswordEncoder passwordEncoder() {
        // O BCryptPasswordEncoder é uma implementação do PasswordEncoder.
        // Ele usa o algoritmo BCrypt, que é muito seguro para armazenar senhas.
        // O BCrypt gera um "hash" diferente toda vez, mesmo para a mesma senha,
        // o que dificulta ataques de força bruta ou comparação direta.
        return new BCryptPasswordEncoder();
    }
}
