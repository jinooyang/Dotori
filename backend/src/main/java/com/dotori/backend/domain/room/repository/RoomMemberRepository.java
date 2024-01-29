package com.dotori.backend.domain.room.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dotori.backend.domain.room.model.entity.RoomMember;

public interface RoomMemberRepository extends JpaRepository<RoomMember, Long> {

}
