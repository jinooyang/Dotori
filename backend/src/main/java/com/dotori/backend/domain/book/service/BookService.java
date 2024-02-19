package com.dotori.backend.domain.book.service;

import java.util.List;
import java.util.stream.Collectors;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import com.dotori.backend.domain.book.model.dto.BookDto;
import com.dotori.backend.domain.book.model.dto.BookMapper;
import com.dotori.backend.domain.book.model.dto.RoleDto;
import com.dotori.backend.domain.book.model.entity.Book;
import com.dotori.backend.domain.book.model.entity.Role;
import com.dotori.backend.domain.book.repository.BookRepository;
import com.dotori.backend.domain.book.repository.RoleRepository;

import lombok.RequiredArgsConstructor;

@Service
@Transactional
@RequiredArgsConstructor
public class BookService {

	private final BookRepository bookRepository;

	private final RoleRepository roleRepository;

	@Cacheable(value = "books")
	public List<BookDto> getBooks() {
		return bookRepository.findAll()
			.stream()
			.map(BookMapper::toBookDto)
			.collect(Collectors.toList());
	}

	@Cacheable(value = "book", key = "#bookId")
	public BookDto getBook(Long bookId) {
		Book book = bookRepository.findById(bookId).orElseThrow(
			() -> new EntityNotFoundException("해당하는 책이 존재하지 않습니다.")
		);

		return BookMapper.toBookDto(book);
	}

	@Cacheable(value = "roles", key = "#bookId")
	public List<RoleDto> getRolesByBookId(Long bookId) {
		List<Role> roleList = roleRepository.findByBook_BookId(bookId);

		return roleList.stream()
			.map(BookMapper::toRoleDto)
			.collect(Collectors.toList());
	}
}