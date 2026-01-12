package com.example.spring_security_jwt_auth.repositories;

import com.example.spring_security_jwt_auth.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {
    Optional<User> findByEmail(String email);
}
