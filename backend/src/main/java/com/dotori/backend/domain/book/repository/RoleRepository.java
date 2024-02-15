package com.dotori.backend.domain.book.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.dotori.backend.domain.book.model.entity.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
	List<Role> findByBook_BookId(Long bookId);
}