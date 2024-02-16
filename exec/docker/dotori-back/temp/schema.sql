use dotori;

-- avatar
create table avatar
(
    avatar_id bigint auto_increment
        primary key,
    name      varchar(20)  null,
    path      varchar(100) null,
    member_id bigint       not null,
    constraint UK_ln8rcc6vgs1umxuc1jmx835gk
        unique (path),
    constraint FK19gyayk5srtmmrwft2cu1rr0v
        foreign key (member_id) references member (member_id)
)
    collate = utf8mb4_unicode_ci;

-- book
create table book
(
    book_id  bigint auto_increment
        primary key,
    author   varchar(20)  null,
    book_img varchar(100) null,
    role_cnt int          null,
    title    varchar(20)  null,
    summary  varchar(300) null
)
    collate = utf8mb4_unicode_ci;

-- member
create table member
(
    member_id   bigint auto_increment
        primary key,
    created_at  datetime(6)  null,
    updated_at  datetime(6)  null,
    nickname    varchar(255) null,
    profile_img varchar(100) null,
    constraint UK_hh9kg6jti4n1eoiertn2k6qsc
        unique (nickname)
)
    collate = utf8mb4_unicode_ci;

-- member_video
create table member_video
(
    member_video_id bigint auto_increment
        primary key,
    created_at      datetime(6) null,
    updated_at      datetime(6) null,
    book_id         bigint      null,
    member_id       bigint      not null,
    video_id        bigint      not null,
    constraint FKcs5b2umhclusp3awmc7gdgrqi
        foreign key (member_id) references member (member_id),
    constraint FKp627ppn3og0f0endppi9gbgbu
        foreign key (video_id) references video (video_id)
)
    collate = utf8mb4_unicode_ci;

-- role
create table role
(
    role_id   bigint auto_increment
        primary key,
    mask_path varchar(100) null,
    name      varchar(10)  null,
    book_id   bigint       null,
    constraint FKo6vcoufchqo7kemqqynxorna3
        foreign key (book_id) references book (book_id)
)
    collate = utf8mb4_unicode_ci;

-- room
create table room
(
    room_id      bigint auto_increment
        primary key,
    created_at   datetime(6) null,
    updated_at   datetime(6) null,
    host_id      bigint      null,
    is_public    bit         null,
    is_recording bit         null,
    join_cnt     int         null,
    limit_cnt    int         null,
    password     varchar(50) null,
    session_id   varchar(50) null,
    title        varchar(20) null,
    book_id      bigint      not null,
    constraint FKvokddjbkrl2em84s9hctetmk
        foreign key (book_id) references book (book_id)
)
    collate = utf8mb4_unicode_ci;


-- room_member
create table room_member
(
    room_member_id bigint auto_increment
        primary key,
    created_at     datetime(6) null,
    updated_at     datetime(6) null,
    avatar_id      bigint      null,
    is_ready       bit         null,
    role_id        bigint      null,
    member_id      bigint      null,
    room_id        bigint      null,
    constraint FKav1svcloqr7ue4dhsgkj5t4a5
        foreign key (member_id) references member (member_id),
    constraint FKlmp67erahqx7u5shbkc12p0lw
        foreign key (room_id) references room (room_id)
)
    collate = utf8mb4_unicode_ci;


-- scene
create table scene
(
    scene_id         bigint auto_increment
        primary key,
    background_image varchar(100) null,
    scene_order      int          null,
    book_id          bigint       not null,
    constraint FKt4t7bx5ox89ig3q5vbysubsvn
        foreign key (book_id) references book (book_id)
)
    collate = utf8mb4_unicode_ci;

-- video
create table video
(
    video_id   bigint auto_increment
        primary key,
    created_at datetime(6)  null,
    updated_at datetime(6)  null,
    path       varchar(100) null
)
    collate = utf8mb4_unicode_ci;

-- scene_video
create table scene_video
(
    scene_video_id bigint auto_increment
        primary key,
    created_at     datetime(6)  null,
    updated_at     datetime(6)  null,
    path           varchar(100) null,
    scene_order    int          null,
    room_id        bigint       not null,
    constraint FK1ftayo16j5mjvgebgpo5ndt2h
        foreign key (room_id) references room (room_id)
)
    collate = utf8mb4_unicode_ci;

-- script
create table script
(
    script_id    bigint auto_increment
        primary key,
    content      varchar(100) null,
    script_order int          null,
    role_id      bigint       not null,
    scene_id     bigint       not null,
    constraint FKl9tlxsl8ra8aj4oif37ruhdxm
        foreign key (scene_id) references scene (scene_id),
    constraint FKlv4inwfdmtc1xg16ju3gg5o9i
        foreign key (role_id) references role (role_id)
)
    collate = utf8mb4_unicode_ci;

