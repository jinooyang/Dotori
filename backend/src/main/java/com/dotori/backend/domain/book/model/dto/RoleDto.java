package com.dotori.backend.domain.book.model.dto;

import static lombok.AccessLevel.*;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor(access = PRIVATE)
@AllArgsConstructor
public class RoleDto {
	private Long roleId;
	private String name;
	private String maskPath;
	private String maskThumbnailPath;
}