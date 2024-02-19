package com.dotori.backend.domain.book.model.dto;

import static lombok.AccessLevel.*;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@NoArgsConstructor(access = PRIVATE)
@AllArgsConstructor
public class ScriptDto {
	private Long scriptId;
	private RoleDto roleDto;
	private int scriptOrder;
	private String content;
}
