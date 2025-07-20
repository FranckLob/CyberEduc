package com.franck.springsecurityjwtoken.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.franck.springsecurityjwtoken.model.DBUser;

public interface DBUserRepository extends JpaRepository<DBUser, Integer> {
    public DBUser findDbUserByUsername(String username);
    
}