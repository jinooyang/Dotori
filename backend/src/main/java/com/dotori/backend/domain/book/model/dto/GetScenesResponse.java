package com.dotori.backend.domain.book.model.dto;

import java.util.List;
import java.util.stream.Collectors;

import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
public class GetScenesResponse {
	private final List<SimpleSceneDto> scenes;

	public GetScenesResponse(List<SceneDto> sceneDtos) {
		this.scenes = sceneDtos.stream()
			.map(SimpleSceneDto::of)
			.collect(Collectors.toList());
	}

	@Getter
	@ToString
	public static final class SimpleSceneDto {
		private final Long sceneId;
		private final int sceneOrder;
		private final String backgroundImage;

		private SimpleSceneDto(Long sceneId, int sceneOrder, String backgroundImage) {
			this.sceneId = sceneId;
			this.sceneOrder = sceneOrder;
			this.backgroundImage = backgroundImage;
		}

		private static SimpleSceneDto of(SceneDto sceneDto) {
			return new SimpleSceneDto(
				sceneDto.getSceneId(),
				sceneDto.getSceneOrder(),
				sceneDto.getBackgroundImage()
			);
		}
	}
}
