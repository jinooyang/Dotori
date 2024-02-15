package com.dotori.backend.domain.book.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dotori.backend.domain.book.model.entity.Scene;

public interface SceneRepository extends JpaRepository<Scene, Long> {
	List<Scene> findByBook_BookId(Long bookId);
}
