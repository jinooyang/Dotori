package com.dotori.backend.domain.book.controller;

import static org.springframework.http.MediaType.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.ArrayList;
import java.util.List;

import javax.transaction.Transactional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockCookie;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.dotori.backend.domain.book.model.entity.Book;
import com.dotori.backend.domain.book.model.entity.Role;
import com.dotori.backend.domain.book.model.entity.Scene;
import com.dotori.backend.domain.book.model.entity.Script;
import com.dotori.backend.domain.book.repository.BookRepository;
import com.dotori.backend.domain.book.repository.RoleRepository;
import com.dotori.backend.domain.book.repository.SceneRepository;
import com.dotori.backend.domain.book.service.BookService;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class BookControllerTest {

	@Autowired
	private BookRepository bookRepository;

	@Autowired
	private BookService bookService;

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private SceneRepository sceneRepository;

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private WebApplicationContext context;

	private String accessToken = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJBY2Nlc3NUb2tlbiIsImV4cCI6MTcwOTQ5NjA0NSwiZW1haWwiOiJtb29uYWJjZDhAZ21haWwuY29tIiwicm9sZSI6IlVTRVIifQ.LtD4Thnmvcfdag6P6YIbfD01-QXaqJSNhV2yMou8Bc7sCqRpAvKkpHDCb5RF9ioI-NltOv86WAGGltEvrqj30g";

	@BeforeEach
	public void setup() {
		mockMvc = MockMvcBuilders
			.webAppContextSetup(context)
			.apply(springSecurity()) // 스프링 시큐리티와 함께 MockMvc 설정
			.build();
	}

	@DisplayName("책 목록 조회 테스트")
	@Test
	void getBooks() throws Exception {
		//given
		Book book1 = Book.builder()
			.title("자서전 2")
			.author("조석현")
			.bookImg("책 1 이미지")
			.roleCnt(4)
			.summary("줄거리 1")
			.build();

		Book book2 = Book.builder()
			.title("자서전 2")
			.bookImg("책 2 이미지")
			.roleCnt(4)
			.author("조현석")
			.summary("줄거리 2")
			.build();

		bookRepository.save(book1);
		bookRepository.save(book2);
		MockCookie cookie = new MockCookie("accessToken", accessToken);
		//when
		mockMvc.perform(get("/api/books").cookie(cookie)).andExpect(status().isOk())
			.andExpect(content().contentType(APPLICATION_JSON))
			.andExpect(jsonPath("$.books.size()").value(2L))
			.andExpect(jsonPath("$.books[0].title").value(book1.getTitle()))
			.andExpect(jsonPath("$.books[0].bookImg").value(book1.getBookImg()))
			.andExpect(jsonPath("$.books[0].roleCnt").value(book1.getRoleCnt()))
			.andExpect(jsonPath("$.books[0].author").value(book1.getAuthor()))
			.andExpect(jsonPath("$.books[0].summary").value(book1.getSummary()))
			.andExpect(jsonPath("$.books[1].title").value(book2.getTitle()))
			.andExpect(jsonPath("$.books[1].bookImg").value(book2.getBookImg()))
			.andExpect(jsonPath("$.books[1].roleCnt").value(book2.getRoleCnt()))
			.andExpect(jsonPath("$.books[1].author").value(book2.getAuthor()))
			.andExpect(jsonPath("$.books[1].summary").value(book2.getSummary()))
			.andDo(print());

		//then
	}

	@DisplayName("책 정보 조회 테스트")
	@Test
	void getBook() throws Exception {
		//given
		Book book1 = Book.builder()
			.title("자서전 2")
			.author("조석현")
			.bookImg("책 1 이미지")
			.roleCnt(4)
			.summary("줄거리 1")
			.build();

		bookRepository.save(book1);

		Role role1 = Role.builder().book(book1).maskPath("탈 주소 1").name("역할 1").build();
		Role role2 = Role.builder().book(book1).maskPath("탈 주소 2").name("역할 2").build();

		roleRepository.save(role1);
		roleRepository.save(role2);

		//when

		//then
		MockCookie cookie = new MockCookie("accessToken", accessToken);
		mockMvc.perform(get("/api/books/{bookId}", book1.getBookId()).cookie(cookie))
			.andExpect(status().isOk())
			.andExpect(content().contentType(APPLICATION_JSON))
			.andExpect(jsonPath("$.book.title").value(book1.getTitle()))
			.andExpect(jsonPath("$.book.bookImg").value(book1.getBookImg()))
			.andExpect(jsonPath("$.book.roleCnt").value(book1.getRoleCnt()))
			.andExpect(jsonPath("$.book.author").value(book1.getAuthor()))
			.andExpect(jsonPath("$.book.summary").value(book1.getSummary()))
			.andExpect(jsonPath("$.roles.size()").value(2))
			.andExpect(jsonPath("$.roles[0].name").value(role1.getName()))
			.andExpect(jsonPath("$.roles[0].maskPath").value(role1.getMaskPath()))
			.andExpect(jsonPath("$.roles[1].name").value(role2.getName()))
			.andExpect(jsonPath("$.roles[1].maskPath").value(role2.getMaskPath()))
			.andDo(print())
		;
	}

	@Test
	@DisplayName("책에 해당하는 장면목록 가져오기 - 성공")
	void getScenesTest() throws Exception {
		Book book = Book.builder()
			.title("title1")
			.author("author1")
			.roleCnt(1)
			.bookImg("bookImg1")
			.summary("summary1")
			.build();
		bookRepository.save(book);

		List<Scene> scenes = new ArrayList<>();
		Scene scene1 = Scene.builder()
			.backgroundImage("bgImg1")
			.sceneOrder(1)
			.book(book)
			.build();

		Scene scene2 = Scene.builder()
			.backgroundImage("bgImg2")
			.sceneOrder(2)
			.book(book)
			.build();

		Scene scene3 = Scene.builder()
			.backgroundImage("bgImg3")
			.sceneOrder(3)
			.book(book)
			.build();
		scenes.add(scene1);
		scenes.add(scene2);
		scenes.add(scene3);
		sceneRepository.saveAll(scenes);
		MockCookie cookie = new MockCookie("accessToken", accessToken);
		mockMvc.perform(get("/api/books/{bookId}/scenes", book.getBookId()).cookie(cookie))
			.andExpect(status().isOk())
			.andExpect(content().contentType(APPLICATION_JSON))
			.andExpect(jsonPath("$.scenes.size()").value(3L))
			.andExpect(jsonPath("$.scenes[0].sceneId").value(scene1.getSceneId()))
			.andExpect(jsonPath("$.scenes[0].sceneOrder").value(scene1.getSceneOrder()))
			.andExpect(jsonPath("$.scenes[0].backgroundImage").value(scene1.getBackgroundImage()))
			.andExpect(jsonPath("$.scenes[1].sceneId").value(scene2.getSceneId()))
			.andExpect(jsonPath("$.scenes[1].sceneOrder").value(scene2.getSceneOrder()))
			.andExpect(jsonPath("$.scenes[1].backgroundImage").value(scene2.getBackgroundImage()))
			.andExpect(jsonPath("$.scenes[2].sceneId").value(scene3.getSceneId()))
			.andExpect(jsonPath("$.scenes[2].sceneOrder").value(scene3.getSceneOrder()))
			.andExpect(jsonPath("$.scenes[2].backgroundImage").value(scene3.getBackgroundImage()))
			.andDo(print());
	}

	@Test
	@DisplayName("장면 세부 정보 가져오기 - 성공")
	void getSceneTest() throws Exception {
		Book book = Book.builder()
			.title("title1")
			.author("author1")
			.roleCnt(1)
			.bookImg("bookImg1")
			.summary("summary1")
			.build();
		bookRepository.save(book);

		Scene scene = Scene.builder()
			.backgroundImage("bgImg1")
			.sceneOrder(1)
			.book(book)
			.build();

		Role role1 = Role.builder()
			.book(book)
			.name("name1")
			.maskPath("maskPath1")
			.build();

		Role role2 = Role.builder()
			.book(book)
			.name("name2")
			.maskPath("maskPath2")
			.build();

		roleRepository.save(role1);
		roleRepository.save(role2);

		Script script1 = Script.builder()
			.scene(scene)
			.role(role1)
			.content("content1")
			.scriptOrder(1)
			.build();

		Script script2 = Script.builder()
			.scene(scene)
			.role(role2)
			.content("content2")
			.scriptOrder(2)
			.build();
		scene.addScript(script1);
		scene.addScript(script2);
		sceneRepository.save(scene);
		MockCookie cookie = new MockCookie("accessToken", accessToken);
		mockMvc.perform(
				get("/api/books/{bookId}/scenes/{sceneId}", book.getBookId(), scene.getSceneId()).cookie(cookie))
			.andExpect(status().isOk())
			.andExpect(content().contentType(APPLICATION_JSON))
			.andExpect(jsonPath("$.sceneDetailDto").isNotEmpty())
			.andExpect(jsonPath("$.sceneDetailDto.sceneId").value(scene.getSceneId()))
			.andExpect(jsonPath("$.sceneDetailDto.backgroundImage").value(scene.getBackgroundImage()))
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto").isArray())
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[0].scriptId").value(script1.getScriptId()))
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[0].scriptOrder").value(script1.getScriptOrder()))
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[0].content").value(script1.getContent()))
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[0].roleDto").isNotEmpty())
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[0].roleDto.roleId").value(script1.getRole().getRoleId()))
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[0].roleDto.name").value(script1.getRole().getName()))
			.andExpect(
				jsonPath("$.sceneDetailDto.scriptDto[0].roleDto.maskPath").value(script1.getRole().getMaskPath()))
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[1].scriptId").value(script2.getScriptId()))
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[1].scriptOrder").value(script2.getScriptOrder()))
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[1].content").value(script2.getContent()))
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[1].roleDto").isNotEmpty())
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[1].roleDto.roleId").value(script2.getRole().getRoleId()))
			.andExpect(jsonPath("$.sceneDetailDto.scriptDto[1].roleDto.name").value(script2.getRole().getName()))
			.andExpect(
				jsonPath("$.sceneDetailDto.scriptDto[1].roleDto.maskPath").value(script2.getRole().getMaskPath()))
			.andDo(print());
	}

	@Test
	@DisplayName("책 상세정보 조회 테스트 - 책, 장면, 대사, 역할 포함")
	void getBookDetailByBookId() throws Exception {
		Book book = Book.builder()
			.title("title1")
			.author("author1")
			.roleCnt(1)
			.bookImg("bookImg1")
			.summary("summary1")
			.build();
		bookRepository.save(book);

		Scene scene = Scene.builder()
			.backgroundImage("bgImg1")
			.sceneOrder(1)
			.book(book)
			.build();

		Role role1 = Role.builder()
			.book(book)
			.name("name1")
			.maskPath("maskPath1")
			.build();

		Role role2 = Role.builder()
			.book(book)
			.name("name2")
			.maskPath("maskPath2")
			.build();

		roleRepository.save(role1);
		roleRepository.save(role2);

		Script script1 = Script.builder()
			.scene(scene)
			.role(role1)
			.content("content1")
			.scriptOrder(1)
			.build();

		Script script2 = Script.builder()
			.scene(scene)
			.role(role2)
			.content("content2")
			.scriptOrder(2)
			.build();
		scene.addScript(script1);
		scene.addScript(script2);
		sceneRepository.save(scene);
		MockCookie cookie = new MockCookie("accessToken", accessToken);
		mockMvc.perform(get("/api/books/{bookId}/detail", book.getBookId()).cookie(cookie))
			.andExpect(status().isOk())
			.andExpect(content().contentType(APPLICATION_JSON))
			.andDo(print());
	}
}