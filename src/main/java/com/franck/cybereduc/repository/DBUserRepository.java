package com.franck.cybereduc.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.franck.cybereduc.model.DBUser;
import com.franck.cybereduc.model.Role;

public interface DBUserRepository extends JpaRepository<DBUser, Integer> {
    
    public Optional<DBUser> findDbUserByUsername(String username);

    public Optional<DBUser> findDbUserByRole(Role role);

    public long countByRole(Role role);
    
}