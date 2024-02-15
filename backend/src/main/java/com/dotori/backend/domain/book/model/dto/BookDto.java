package com.dotori.backend.domain.book.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class BookDto {
	private Long bookId;
	private String title;
	private String bookImg;
	private String author;
	private String summary;
	private int roleCnt;
}