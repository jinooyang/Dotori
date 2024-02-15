package com.dotori.backend.domain.book.model.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@RequiredArgsConstructor
public class GetSceneResponse {
	private final SceneDetailDto sceneDetailDto;
}
