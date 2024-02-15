package com.dotori.backend.domain.member.model.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class ProfileImageUpdateResponse {
	private final String profileImage;
}
