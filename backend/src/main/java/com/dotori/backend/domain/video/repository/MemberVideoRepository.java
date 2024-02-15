package com.dotori.backend.domain.video.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dotori.backend.domain.member.model.entity.MemberVideo;

public interface MemberVideoRepository extends JpaRepository<MemberVideo, Long> {
	List<MemberVideo> findByMember_MemberId(Long memberId);
}
