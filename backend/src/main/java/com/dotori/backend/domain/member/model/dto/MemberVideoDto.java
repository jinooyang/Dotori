package com.dotori.backend.domain.member.model.dto;

import java.time.LocalDateTime;

import com.dotori.backend.domain.video.model.dto.VideoDto;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@Builder
@RequiredArgsConstructor
public class MemberVideoDto {
	private final String bookTitle;
	private final Long videoId;
	private final String createdAt;
}
