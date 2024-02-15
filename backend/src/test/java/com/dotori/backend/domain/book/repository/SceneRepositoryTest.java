package com.dotori.backend.domain.book.repository;

import java.util.ArrayList;
import java.util.List;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.annotation.Transactional;

import com.dotori.backend.domain.book.TestRedisSessionConfig;
import com.dotori.backend.domain.book.model.entity.Book;
import com.dotori.backend.domain.book.model.entity.Role;
import com.dotori.backend.domain.book.model.entity.Scene;
import com.dotori.backend.domain.book.model.entity.Script;

@DataJpaTest
@Import(TestRedisSessionConfig.class)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class SceneRepositoryTest {
	@Autowired
	private BookRepository bookRepository;

	@Autowired
	private SceneRepository sceneRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Test
	@Transactional
	@DisplayName("getScenes - success")
	void getScenes() {
		// given
		Book savedBook = bookRepository.save(
			Book.builder()
				.title("title1")
				.author("author1")
				.bookImg("bookImg1")
				.summary("summary1")
				.roleCnt(1)
				.build()
		);

		Scene savedScene1 = Scene.builder()
			.sceneOrder(1)
			.backgroundImage("bgImg1")
			.book(savedBook)
			.build();
		Scene savedScene2 = Scene.builder()
			.sceneOrder(2)
			.backgroundImage("bgImg2")
			.book(savedBook)
			.build();
		Scene savedScene3 = Scene.builder()
			.sceneOrder(3)
			.backgroundImage("bgImg3")
			.book(savedBook)
			.build();
		List<Scene> savedScenes = new ArrayList<>();
		savedScenes.add(savedScene1);
		savedScenes.add(savedScene2);
		savedScenes.add(savedScene3);

		sceneRepository.saveAll(savedScenes);

		// when
		List<Scene> foundScenes = sceneRepository.findByBook_BookId(savedBook.getBookId());

		// then
		Assertions.assertThat(foundScenes.size()).isEqualTo(savedScenes.size());
		Assertions.assertThat(foundScenes)
			.usingRecursiveComparison()
			.isEqualTo(savedScenes);
	}

	@Test
	@DisplayName("getScene - success")
	void getScene() {
		// given
		Book savedBook = bookRepository.save(
			Book.builder()
				.title("title1")
				.author("author1")
				.bookImg("bookImg1")
				.summary("summary1")
				.roleCnt(1)
				.build()
		);

		Role savedRole1 = roleRepository.save(Role.builder()
			.book(savedBook)
			.maskPath("maskPath1")
			.name("name1")
			.build()
		);

		Role savedRole2 = roleRepository.save(Role.builder()
			.book(savedBook)
			.maskPath("maskPath1")
			.name("name1")
			.build()
		);

		Scene savedScene = Scene.builder()
			.sceneOrder(1)
			.backgroundImage("bgImg1")
			.book(savedBook)
			.build();

		Script savedScript1 = Script.builder()
			.scene(savedScene)
			.role(savedRole1)
			.content("content1")
			.scriptOrder(1)
			.build();

		Script savedScript2 = Script.builder()
			.scene(savedScene)
			.role(savedRole2)
			.content("content2")
			.scriptOrder(2)
			.build();

		Script savedScript3 = Script.builder()
			.scene(savedScene)
			.role(savedRole1)
			.content("content3")
			.scriptOrder(3)
			.build();

		List<Script> savedScripts = new ArrayList<>();
		savedScripts.add(savedScript1);
		savedScripts.add(savedScript2);
		savedScripts.add(savedScript3);
		savedScene.addScripts(savedScripts);
		sceneRepository.save(savedScene);

		// when
		Scene foundScene = sceneRepository.findById(savedScene.getSceneId()).get();

		// then
		Assertions.assertThat(foundScene).isEqualTo(savedScene);
		Assertions.assertThat(foundScene.getScripts())
			.usingRecursiveComparison()
			.isEqualTo(savedScripts);
	}
}