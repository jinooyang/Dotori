package com.dotori.backend.domain.video.model.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import org.springframework.web.multipart.MultipartFile;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@RequiredArgsConstructor
public class VideoChunkUploadRequest {
	@NotBlank
	private final String fileName;

	@NotNull
	private final int chunkNumber;

	@NotNull
	private final MultipartFile chunkFile;

	@NotNull
	private final boolean isEnd;
}
