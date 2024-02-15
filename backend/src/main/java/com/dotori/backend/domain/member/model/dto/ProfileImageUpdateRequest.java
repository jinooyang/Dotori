package com.dotori.backend.domain.member.model.dto;

import javax.validation.constraints.NotNull;

import org.springframework.web.multipart.MultipartFile;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class ProfileImageUpdateRequest {
	@NotNull
	private final MultipartFile profileImage;
}
