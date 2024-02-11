package com.dotori.backend.domain.member.service;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;

import javax.transaction.Transactional;

import org.springframework.stereotype.Service;

import com.dotori.backend.domain.book.service.BookService;
import com.dotori.backend.domain.member.model.dto.MemberVideoDto;
import com.dotori.backend.domain.member.model.entity.MemberVideo;
import com.dotori.backend.domain.video.repository.MemberVideoRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class MemberService {
	private final MemberVideoRepository memberVideoRepository;
	private final BookService bookService;

	@Transactional
	public List<MemberVideoDto> getMemberVideos(Long memberId){
		List<MemberVideo> memberVideos = memberVideoRepository.findByMember_MemberId(memberId);

		return memberVideos.stream()
			.map(memberVideo -> MemberVideoDto.builder()
				.bookTitle(bookService.getBook(memberVideo.getBookId()).getTitle())
				.videoId(memberVideo.getVideo().getVideoId())
				.createdAt(memberVideo.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy년 MM월 dd일 HH시 mm분")))
				.build())
			.collect(Collectors.toList());
	}
}
