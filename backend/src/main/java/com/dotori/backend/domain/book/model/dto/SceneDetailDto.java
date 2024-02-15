package com.dotori.backend.domain.book.model.dto;

import java.util.List;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@RequiredArgsConstructor
public class SceneDetailDto {
	private final Long sceneId;
	private final int sceneOrder;
	private final String backgroundImage;
	private final List<ScriptDto> scriptDto;
}
