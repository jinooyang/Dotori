package com.dotori.backend.domain.video.model.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@RequiredArgsConstructor
public class VideoDto {
	private final Long videoId;
	private final String path;
}
