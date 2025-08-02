package com.franck.cybereduc.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.franck.cybereduc.model.DBUser;

public interface DBUserRepository extends JpaRepository<DBUser, Integer> {
    public DBUser findDbUserByUsername(String username);
    
}