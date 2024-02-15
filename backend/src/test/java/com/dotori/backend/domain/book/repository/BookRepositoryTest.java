package com.dotori.backend.domain.book.repository;

import static org.assertj.core.api.Assertions.*;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.context.annotation.Import;

import com.dotori.backend.domain.book.TestRedisSessionConfig;
import com.dotori.backend.domain.book.model.entity.Book;

@DataJpaTest
@Import(TestRedisSessionConfig.class)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class BookRepositoryTest {

	@Autowired
	private BookRepository bookRepository;

	@Autowired
	private TestEntityManager testEntityManager;

	@DisplayName("책 목록 조회 테스트")
	@Test
	void getBooks() {
		//given
		Book bookWithAuthor = Book.builder()
			.title("자서전1")
			.author("조석현")
			.bookImg("책 1 이미지")
			.roleCnt(4)
			.build();

		Book bookWithNoAuthor = Book.builder()
			.title("자서전1")
			.bookImg("책 2 이미지")
			.roleCnt(4)
			.build();

		//when
		bookRepository.save(bookWithAuthor);
		bookRepository.save(bookWithNoAuthor);

		List<Book> bookList = bookRepository.findAll();

		//then
		assertThat(bookList.size()).isEqualTo(2);
	}

	@DisplayName("책 정보 조회 - 모든 책 정보 저장 후 확인")
	@Test
	void getBook() {
		Book bookWithAuthor = Book.builder()
			.title("자서전1")
			.author("조석현")
			.bookImg("책 1 이미지")
			.summary("줄거리 1")
			.roleCnt(4)
			.build();

		//when
		Book save = bookRepository.save(bookWithAuthor);
		Optional<Book> result = bookRepository.findById(save.getBookId());
		Book book = result.get();

		//then
		assertThat(book.getTitle()).isEqualTo("자서전1");
		assertThat(book.getAuthor()).isEqualTo("조석현");
		assertThat(book.getBookImg()).isEqualTo("책 1 이미지");
		assertThat(book.getSummary()).isEqualTo("줄거리 1");
		assertThat(book.getRoleCnt()).isEqualTo(4);

	}

	@DisplayName("책 정보 조회 - 저자 없이 저장 후 확인")
	@Test
	void getBookWithNoAuthor() {
		Book bookWithNoAuthor = Book.builder()
			.title("자서전1")
			.bookImg("책 2 이미지")
			.summary("줄거리 2")
			.roleCnt(4)
			.build();
		;

		//when
		Book book = testEntityManager.persistFlushFind(bookWithNoAuthor);

		// then
		assertThat(book.getTitle()).isEqualTo("자서전1");
		assertThat(book.getAuthor()).isEqualTo("저자 미상");
		assertThat(book.getBookImg()).isEqualTo("책 2 이미지");
		assertThat(book.getSummary()).isEqualTo("줄거리 2");
		assertThat(book.getRoleCnt()).isEqualTo(4);
	}
}