package com.dotori.backend.domain.book.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.dotori.backend.domain.book.model.dto.BookDetailDto;
import com.dotori.backend.domain.book.model.dto.GetSceneResponse;
import com.dotori.backend.domain.book.model.dto.GetScenesResponse;
import com.dotori.backend.domain.book.model.dto.response.GetBookResponse;
import com.dotori.backend.domain.book.model.dto.response.GetBooksResponse;
import com.dotori.backend.domain.book.service.BookService;
import com.dotori.backend.domain.book.service.SceneService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/books")
@RequiredArgsConstructor
public class BookController {

	private final BookService bookService;
	private final SceneService sceneService;

	@GetMapping
	public ResponseEntity<GetBooksResponse> getBooks() {
		return ResponseEntity.ok(new GetBooksResponse(bookService.getBooks()));
	}

	@GetMapping("/{bookId}")
	public ResponseEntity<GetBookResponse> getBook(@PathVariable Long bookId) {
		return ResponseEntity.ok(
			new GetBookResponse(bookService.getBook(bookId), bookService.getRolesByBookId(bookId)));
	}

	@GetMapping("/{bookId}/scenes")
	public ResponseEntity<GetScenesResponse> getScenesByBookId(@PathVariable Long bookId) {
		return ResponseEntity.ok().body(new GetScenesResponse(sceneService.getScenesByBookId(bookId)));
	}

	@GetMapping("/{bookId}/scenes/{sceneId}")
	public ResponseEntity<GetSceneResponse> getSceneBySceneId(@PathVariable Long sceneId) {
		return ResponseEntity.ok()
			.body(new GetSceneResponse(sceneService.getScene(sceneId)));
	}

	@GetMapping("/{bookId}/detail")
	public ResponseEntity<BookDetailDto> getBookDetailByBookId(@PathVariable Long bookId) {
		return ResponseEntity.ok().body(
			BookDetailDto.builder()
				.book(bookService.getBook(bookId))
				.roles(bookService.getRolesByBookId(bookId))
				.scenes(sceneService.getSceneDetailsByBookId(bookId))
				.build()
		);
	}
}