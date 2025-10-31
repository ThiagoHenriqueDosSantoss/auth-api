package com.example.auth_api.entity;

import com.example.auth_api.enums.UserRoles;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/*

     @author thiago.santos

*/
@Entity
@Table(name = "users")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode(of = "idusers")
public class Users implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long idusers;
    @Column(name = "login", nullable = false, unique = true)
    private String login;
    @Column(name = "password", nullable = false)
    private String password;
    @Enumerated(value = EnumType.STRING)
    @Column(name = "role", nullable = false)
    private UserRoles role;

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UserRoles getRole() {
        return role;
    }

    public void setRole(UserRoles role) {
        this.role = role;
    }


    //Métodos da classe UserDetails que é fornecido pelo Spring Security

    //getAuthorites serve para o Spring security consultar as roles que o nosso usuario possui - Ex: (Adimin, Mod, User)
    //Aqui precisamos fazer um de-para das roles que nos temos com a Spring security espera receber
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Esse método devolve (retorna) a lista de "autoridades" ou "permissões"
        // que o usuário tem dentro do sistema.
        // É usado pelo Spring Security para saber o que o usuário pode ou não fazer.

        // Verifica se o papel (role) do usuário é ADMIN
        if (this.role == UserRoles.ADMIN) {
            // Se for ADMIN, ele recebe duas permissões:
            // 1. ROLE_ADMIN → pode fazer tudo o que um administrador faz
            // 2. ROLE_USER → também pode fazer tudo o que um usuário comum faz
            return List.of(
                    new SimpleGrantedAuthority("ROLE_ADMIN"),
                    new SimpleGrantedAuthority("ROLE_USER")
            );
        } else {
            // Se não for ADMIN (ou seja, for apenas um usuário comum),
            // ele recebe apenas a permissão de usuário.
            return List.of(new SimpleGrantedAuthority("ROLE_USER"));
        }
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return login; //Retorno do getUsername por padrão é "" mas nos iremos retornar o login do nosso usuario
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
