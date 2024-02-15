package com.dotori.backend.domain.video.model.dto.request;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Getter
@ToString
@NoArgsConstructor
@AllArgsConstructor
public class SceneVideoSaveRequest {
	@NotNull
	private Long roomId;
	@NotNull
	private Integer sceneOrder;
	@NotBlank
	private String savedPath;
}
