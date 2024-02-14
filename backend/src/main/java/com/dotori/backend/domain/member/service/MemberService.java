package com.dotori.backend.domain.member.service;

import java.io.File;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.persistence.EntityNotFoundException;
import javax.transaction.Transactional;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.dotori.backend.common.config.PathProperty;
import com.dotori.backend.domain.book.service.BookService;
import com.dotori.backend.domain.member.model.dto.MemberVideoDto;
import com.dotori.backend.domain.member.model.dto.ProfileImageUpdateRequest;
import com.dotori.backend.domain.member.model.entity.Member;
import com.dotori.backend.domain.member.model.entity.MemberVideo;
import com.dotori.backend.domain.member.repository.MemberRepository;
import com.dotori.backend.domain.video.repository.MemberVideoRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class MemberService {
	private final MemberRepository memberRepository;
	private final MemberVideoRepository memberVideoRepository;
	private final BookService bookService;
	private final File profileImageSaveDirectory;
	private final PathProperty pathProperty;

	@Transactional
	public List<MemberVideoDto> getMemberVideos(Long memberId) {
		List<MemberVideo> memberVideos = memberVideoRepository.findByMember_MemberId(memberId);

		return memberVideos.stream()
			.map(memberVideo -> MemberVideoDto.builder()
				.bookTitle(bookService.getBook(memberVideo.getBookId()).getTitle())
				.videoId(memberVideo.getVideo().getVideoId())
				.path(memberVideo.getVideo().getPath())
				.createdAt(memberVideo.getCreatedAt().format(DateTimeFormatter.ofPattern("yyyy년 MM월 dd일 HH시 mm분")))
				.build())
			.collect(Collectors.toList());
	}

	@Transactional
	public String updateProfileImage(String email, ProfileImageUpdateRequest profileImageUpdateRequest) {
		MultipartFile profileImage = profileImageUpdateRequest.getProfileImage();
		String imageExtension = splitFileName(profileImage.getOriginalFilename())[1];
		String savedName = UUID.randomUUID() + imageExtension;
		File updatedProfileImage = profileImageSaveDirectory.toPath().resolve(savedName).toFile();

		try {
			profileImage.transferTo(updatedProfileImage);
		} catch (IOException e) {
			log.info("image save failed" + e);
			throw new RuntimeException(e);
		}

		String savedPath = pathProperty.getDOMAIN() + pathProperty.getPROFILE_IMAGE_DB_PATH() + savedName;

		Member member = memberRepository.findByEmail(email)
			.orElseThrow(EntityNotFoundException::new);
		member.updateProfileImg(savedPath);
		memberRepository.save(member);

		return savedPath;
	}

	private String[] splitFileName(String originalFileName) {
		int idx = originalFileName.lastIndexOf(".");
		String[] result = {originalFileName, ".png"};
		if (idx > 0) {
			result[0] = originalFileName.substring(0, idx);
			result[1] = originalFileName.substring(idx);
		}
		return result;
	}
}

