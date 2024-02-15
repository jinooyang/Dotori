package com.dotori.backend.domain.video.model.dto.request;

import java.util.List;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@RequiredArgsConstructor
public class VideoMergeRequest {
	private final List<String> paths;
}
