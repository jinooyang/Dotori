package com.dotori.backend.domain.video.controller;

import static org.springframework.http.MediaType.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.ArrayList;
import java.util.stream.Stream;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockCookie;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.dotori.backend.domain.book.model.entity.Book;
import com.dotori.backend.domain.book.repository.BookRepository;
import com.dotori.backend.domain.room.model.entity.Room;
import com.dotori.backend.domain.room.repository.RoomRepository;
import com.dotori.backend.domain.video.model.dto.request.SceneVideoSaveRequest;
import com.dotori.backend.domain.video.model.entity.SceneVideo;
import com.dotori.backend.domain.video.repository.SceneVideoRepository;
import com.dotori.backend.domain.video.repository.VideoRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class VideoControllerTest {
	@Autowired
	private BookRepository bookRepository;

	@Autowired
	private VideoRepository videoRepository;

	@Autowired
	private SceneVideoRepository sceneVideoRepository;

	@Autowired
	private RoomRepository roomRepository;

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private WebApplicationContext context;

	@Autowired
	private ObjectMapper objectMapper;

	private String accessToken = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJBY2Nlc3NUb2tlbiIsImV4cCI6MTcwOTQ5NjA0NSwiZW1haWwiOiJtb29uYWJjZDhAZ21haWwuY29tIiwicm9sZSI6IlVTRVIifQ.LtD4Thnmvcfdag6P6YIbfD01-QXaqJSNhV2yMou8Bc7sCqRpAvKkpHDCb5RF9ioI-NltOv86WAGGltEvrqj30g";

	@BeforeEach
	public void setup() {
		mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()) // 스프링 시큐리티와 함께 MockMvc 설정
			.build();
	}

	@Test
	@DisplayName("장면 영상 저장 - 성공")
	void saveSceneVideo_success() throws Exception {
		// given
		Book savedBook = Book.builder()
			.author("author")
			.title("bookTitle")
			.roleCnt(3)
			.summary("summary")
			.bookImg("bookImg")
			.build();
		bookRepository.save(savedBook);

		Room savedRoom = roomRepository.save(Room.builder()
			.book(savedBook)
			.title("roomTitle")
			.hostId(1L)
			.joinCnt(3)
			.isRecording(false)
			.isPublic(false)
			.limitCnt(3)
			.roomMembers(new ArrayList<>())
			.build());

		MockCookie cookie = new MockCookie("accessToken", accessToken);
		// when
		SceneVideoSaveRequest sceneVideoSaveRequest = new SceneVideoSaveRequest(savedRoom.getRoomId(), 1, "savedPath");
		mockMvc.perform(post("/api/videos/scenes").cookie(cookie)
				.contentType(APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(sceneVideoSaveRequest)))
			.andExpect(status().isCreated())
			.andDo(print());

		// then
		SceneVideo savedSceneVideo = sceneVideoRepository.findAll().get(0);
		Assertions.assertThat(savedSceneVideo.getRoom().getRoomId()).isEqualTo(sceneVideoSaveRequest.getRoomId());
		Assertions.assertThat(savedSceneVideo.getSceneOrder()).isEqualTo(sceneVideoSaveRequest.getSceneOrder());
		Assertions.assertThat(savedSceneVideo.getPath()).isEqualTo(sceneVideoSaveRequest.getSavedPath());
	}

	@DisplayName("장면 영상 저장 - 실패")
	@ParameterizedTest()
	@ArgumentsSource(SceneVideoSaveArgumentProvider.class)
	void saveSceneVideo_fail(SceneVideoSaveRequest sceneVideoSaveRequest) throws Exception {
		MockCookie cookie = new MockCookie("accessToken", accessToken);
		mockMvc.perform(post("/api/videos/scenes").cookie(cookie)
				.contentType(APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(sceneVideoSaveRequest)))
			.andExpect(status().isBadRequest())
			.andDo(print());
	}

	static class SceneVideoSaveArgumentProvider implements ArgumentsProvider {
		@Override
		public Stream<? extends Arguments> provideArguments(ExtensionContext context) throws Exception {
			return Stream.of(
				new SceneVideoSaveRequest(null, 1, "savedPath"),
				new SceneVideoSaveRequest(1L, null, "savedPath"),
				new SceneVideoSaveRequest(1L, 1, null)
			).map(Arguments::of);
		}
	}
}