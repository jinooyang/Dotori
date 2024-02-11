package com.dotori.backend.domain.member.model.dto;

import java.util.List;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public class GetMemberVideosResponse {
	private final List<MemberVideoDto> videos;
}
