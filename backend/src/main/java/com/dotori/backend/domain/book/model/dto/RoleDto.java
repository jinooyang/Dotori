package com.dotori.backend.domain.book.model.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@Builder
@RequiredArgsConstructor
public class RoleDto {
	private final Long roleId;
	private final String name;
	private final String maskPath;
	private final String maskThumbnailPath;
}