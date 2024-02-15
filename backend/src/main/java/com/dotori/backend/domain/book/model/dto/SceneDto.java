package com.dotori.backend.domain.book.model.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@RequiredArgsConstructor
public class SceneDto {
	private final Long sceneId;
	private final int sceneOrder;
	private final String backgroundImage;
	private final BookDto bookDto;
}
