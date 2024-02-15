package com.dotori.backend.domain.book.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.dotori.backend.domain.book.model.dto.BookDto;
import com.dotori.backend.domain.book.model.dto.BookMapper;
import com.dotori.backend.domain.book.model.dto.SceneDetailDto;
import com.dotori.backend.domain.book.model.dto.SceneDto;
import com.dotori.backend.domain.book.model.entity.Book;
import com.dotori.backend.domain.book.model.entity.Role;
import com.dotori.backend.domain.book.model.entity.Scene;
import com.dotori.backend.domain.book.model.entity.Script;
import com.dotori.backend.domain.book.repository.SceneRepository;

@ExtendWith(MockitoExtension.class)
class SceneServiceTest {
	@InjectMocks
	SceneService sceneService;

	@Mock
	SceneRepository sceneRepository;

	@Test
	@DisplayName("scenesService.getScenes test - success")
	void getScenes() {
		Book savedBook = Book.builder()
			.title("title1")
			.author("author1")
			.bookImg("bookImg1")
			.summary("summary1")
			.build();

		List<Scene> scenes = new ArrayList<>();
		scenes.add(Scene.builder()
			.book(savedBook)
			.sceneOrder(1)
			.backgroundImage("bookImg1")
			.build()
		);
		scenes.add(Scene.builder()
			.book(savedBook)
			.sceneOrder(1)
			.backgroundImage("bookImg1")
			.build()
		);
		scenes.add(Scene.builder()
			.book(savedBook)
			.sceneOrder(1)
			.backgroundImage("bookImg1")
			.build()
		);

		when(sceneRepository.findByBook_BookId(anyLong()))
			.thenReturn(scenes);

		// verify(sceneRepository).findById();

		List<SceneDto> result = sceneService.getScenesByBookId(anyLong());

		assertThat(result.size())
			.isEqualTo(scenes.size());

		assertThat(result)
			.usingRecursiveComparison()
			.ignoringFieldsOfTypes(BookDto.class)
			.isEqualTo(scenes);

		assertThat(result.get(0).getBookDto())
			.usingRecursiveComparison()
			.isEqualTo(savedBook);

		verify(sceneRepository, times(1)).findByBook_BookId(anyLong());
	}

	@Test
	@DisplayName("scenesService.getScene test - success")
	void getScene() {
		// given
		Book savedBook = Book.builder()
			.title("title1")
			.author("author1")
			.bookImg("bookImg1")
			.roleCnt(1)
			.build();

		Scene savedScene = Scene.builder()
			.backgroundImage("bgImg1")
			.sceneOrder(1)
			.book(savedBook)
			.build();

		Role role1 = Role.builder()
			.name("name1")
			.maskPath("maskPath1")
			.book(savedBook)
			.build();

		Role role2 = Role.builder()
			.name("name2")
			.maskPath("maskPath2")
			.book(savedBook)
			.build();

		Script savedScript1 = Script.builder()
			.content("content1")
			.role(role1)
			.scriptOrder(1)
			.build();

		Script savedScript2 = Script.builder()
			.content("content2")
			.role(role2)
			.scriptOrder(1)
			.build();

		List<Script> scripts = new ArrayList<>();
		scripts.add(savedScript1);
		scripts.add(savedScript2);
		savedScene.addScripts(scripts);

		when(sceneRepository.findById(anyLong()))
			.thenReturn(Optional.of(savedScene));
		SceneDetailDto expectSceneDetailDto = BookMapper.toSceneDetailDto(savedScene);

		// when
		SceneDetailDto foundSceneDto = sceneService.getScene(1L);

		// then
		Assertions.assertThat(foundSceneDto)
			.usingRecursiveComparison()
			.isEqualTo(expectSceneDetailDto);

		verify(sceneRepository, times(1)).findById(anyLong());
	}
}