package com.dotori.backend.domain.book.model.dto.response;

import java.util.List;

import com.dotori.backend.domain.book.model.dto.BookDto;
import com.dotori.backend.domain.book.model.dto.RoleDto;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@Builder
@RequiredArgsConstructor
public class GetBookResponse {
	private final BookDto book;
	private final List<RoleDto> roles;
}