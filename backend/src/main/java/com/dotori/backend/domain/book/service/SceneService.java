package com.dotori.backend.domain.book.service;

import static com.dotori.backend.domain.book.model.dto.BookMapper.*;
import static java.util.stream.Collectors.*;

import java.util.List;

import javax.persistence.EntityNotFoundException;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.dotori.backend.domain.book.model.dto.BookMapper;
import com.dotori.backend.domain.book.model.dto.SceneDetailDto;
import com.dotori.backend.domain.book.model.dto.SceneDto;
import com.dotori.backend.domain.book.model.entity.Scene;
import com.dotori.backend.domain.book.repository.SceneRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class SceneService {
	private final SceneRepository sceneRepository;

	@Transactional(readOnly = true)
	public List<SceneDto> getScenesByBookId(Long bookId) {
		return sceneRepository.findByBook_BookId(bookId)
			.stream()
			.map(BookMapper::toSceneDto)
			.collect(toList());
	}

	@Transactional(readOnly = true)
	public SceneDetailDto getScene(Long sceneId) {
		Scene scene = sceneRepository.findById(sceneId)
			.orElseThrow(() -> new EntityNotFoundException("해당하는 scene이 존재하지 않습니다."));
		return toSceneDetailDto(scene);
	}

	@Cacheable(value = "sceneDetails", key = "#bookId")
	@Transactional(readOnly = true)
	public List<SceneDetailDto> getSceneDetailsByBookId(Long bookId) {
		return sceneRepository.findByBook_BookId(bookId)
			.stream()
			.map(BookMapper::toSceneDetailDto)
			.collect(toList());
	}
}
