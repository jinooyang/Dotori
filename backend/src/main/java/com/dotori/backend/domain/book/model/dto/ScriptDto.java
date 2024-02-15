package com.dotori.backend.domain.book.model.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@RequiredArgsConstructor
public class ScriptDto {
	private final Long scriptId;
	private final RoleDto roleDto;
	private final int scriptOrder;
	private final String content;
}
