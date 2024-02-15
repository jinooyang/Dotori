package com.dotori.backend.domain.video.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dotori.backend.domain.video.model.entity.Video;

public interface VideoRepository extends JpaRepository<Video, Long> {
}
