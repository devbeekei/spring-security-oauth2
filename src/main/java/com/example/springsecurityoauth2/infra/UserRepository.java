package com.example.springsecurityoauth2.infra;

import com.example.springsecurityoauth2.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findFirstByEmailOrderByIdAsc(String email);
}
