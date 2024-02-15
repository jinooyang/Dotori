package com.dotori.backend.domain.book.model.dto;

import java.util.List;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@Builder
@RequiredArgsConstructor
public class BookDetailDto {
	private final BookDto book;
	private final List<RoleDto> roles;
	private final List<SceneDetailDto> scenes;
}
