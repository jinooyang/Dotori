package com.dotori.backend.domain.video.model.dto;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;

import org.springframework.web.multipart.MultipartFile;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@RequiredArgsConstructor
public class VideoSceneUploadRequest {
	@Positive
	private final Long roomId;

	@NotNull
	@Positive
	private final int sceneOrder;

	@NotBlank
	private final String fileName;

	@NotNull
	@Min(0)
	private final int chunkNumber;

	@NotNull
	private final MultipartFile chunkFile;

	@NotNull
	private final boolean isEnd;
}
