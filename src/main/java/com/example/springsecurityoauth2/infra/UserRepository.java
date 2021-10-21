package com.example.springsecurityoauth2.infra;

import com.example.springsecurityoauth2.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

}
