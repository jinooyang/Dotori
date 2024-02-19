package com.dotori.backend.domain.book.model.dto;

import static lombok.AccessLevel.*;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@NoArgsConstructor(access = PRIVATE)
@AllArgsConstructor
public class SceneDetailDto {
	private Long sceneId;
	private int sceneOrder;
	private String backgroundImage;
	private List<ScriptDto> scriptDto;
}
