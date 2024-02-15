package com.dotori.backend.domain.book.model.dto;

import static java.util.stream.Collectors.*;

import com.dotori.backend.domain.book.model.entity.Book;
import com.dotori.backend.domain.book.model.entity.Role;
import com.dotori.backend.domain.book.model.entity.Scene;
import com.dotori.backend.domain.book.model.entity.Script;

public class BookMapper {
	public static BookDto toBookDto(Book book) {
		return BookDto.builder()
			.bookId(book.getBookId())
			.title(book.getTitle())
			.bookImg(book.getBookImg())
			.author(book.getAuthor())
			.summary(book.getSummary())
			.roleCnt(book.getRoleCnt())
			.build();
	}

	public static RoleDto toRoleDto(Role role) {
		return RoleDto.builder()
			.roleId(role.getRoleId())
			.name(role.getName())
			.maskPath(role.getMaskPath())
			.maskThumbnailPath(role.getMaskThumbnailPath())
			.build();
	}

	public static SceneDto toSceneDto(Scene scene) {
		return new SceneDto(
			scene.getSceneId(),
			scene.getSceneOrder(),
			scene.getBackgroundImage(),
			toBookDto(scene.getBook())
		);
	}

	public static SceneDetailDto toSceneDetailDto(Scene scene) {
		return new SceneDetailDto(
			scene.getSceneId(),
			scene.getSceneOrder(),
			scene.getBackgroundImage(),
			scene.getScripts()
				.stream().map(BookMapper::toScriptDto)
				.collect(toList())
		);
	}

	private static ScriptDto toScriptDto(Script script) {
		return new ScriptDto(
			script.getScriptId(),
			toRoleDto(script.getRole()),
			script.getScriptOrder(),
			script.getContent()
		);
	}
}