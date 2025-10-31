package com.example.auth_api.repository;

import com.example.auth_api.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserRepository extends JpaRepository<Users, Long> {
    //Vamos implementar um novo metodo para consultar o usuario pelo login

    //O Jpa por sua funcionalidade, quando declaramos um metodo com uma nomenclatura padrao
    //ele consegue identificar pela assinatura do metodo, qual a query ele precisa fazer para retornar
    //as informações que o metodo precisa

    UserDetails findByLogin(String login);
}
