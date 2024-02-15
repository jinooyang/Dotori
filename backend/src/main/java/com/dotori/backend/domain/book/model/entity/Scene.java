package com.dotori.backend.domain.book.model.entity;

import static javax.persistence.CascadeType.*;
import static javax.persistence.FetchType.*;
import static javax.persistence.GenerationType.*;
import static lombok.AccessLevel.*;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.Table;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor(access = PROTECTED)
@Table(name = "scene")
public class Scene {
	@Id
	@Column(name = "scene_id")
	@GeneratedValue(strategy = IDENTITY)
	private Long sceneId;

	@Column(name = "scene_order")
	private int sceneOrder;

	@Column(length = 100, name = "background_image")
	private String backgroundImage;

	@ManyToOne(fetch = LAZY)
	@JoinColumn(name = "book_id", nullable = false)
	private Book book;

	@OneToMany(mappedBy = "scene", cascade = PERSIST, orphanRemoval = true)
	private final List<Script> scripts = new ArrayList<>();

	@Builder
	public Scene(int sceneOrder, String backgroundImage, Book book) {
		this.sceneOrder = sceneOrder;
		this.backgroundImage = backgroundImage;
		this.book = book;
	}

	public void addScript(Script script) {
		this.scripts.add(script);
	}

	public void addScripts(List<Script> scripts) {
		this.scripts.addAll(scripts);
	}
}
