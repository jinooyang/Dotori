package com.dotori.backend.domain.member.model.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@Builder
@RequiredArgsConstructor
public class MemberVideoDto {
	private final String bookTitle;
	private final Long videoId;
	private final String path;
	private final String createdAt;
}
