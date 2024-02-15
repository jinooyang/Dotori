const routes = [
    //메인 페이지
    {
        path: '/',
        component: () => import('layouts/MainPageLayout.vue'),
    },
    //로그인 관련 페이지
    {
        path: '/login-page',
        component: () => import('pages/LoginPage/LoginPage.vue'),
    },

    // 마이페이지
    {
        path: '/my-page',
        component: () => import('layouts/MyPageLayout.vue'),
        children: [
            {
                path: 'info',
                component: () => import('pages/MyPage/MyInfoPage.vue'),
            },
            {
                path: 'collection',
                component: () =>
                    import('pages/MyPage/MyVideoCollectionPage.vue'),
            },
        ],
    },
    //연극페이지
    {
        path: '/recording',
        component: () => import('pages/RecordingPage/RecordingRoom.vue'),
    },
    //목록 페이지(방 목록 보기, 책 목록 보기)
    {
        path: '/list',
        component: () => import('layouts/ListPageLayout.vue'),
        children: [
            {
                path: 'books',
                component: () => import('pages/ListPage/BookListPage.vue'),
            },
            {
                path: 'rooms',
                component: () => import('pages/ListPage/RoomListPage.vue'),
            },
        ],
    },
    //방 생성 모달
    {
        path: '/modal',
        component: () => import('pages/ListPage/NewRoomModal.vue'),
    },
    //대기방 페이지
    {
        path: '/room',
        component: () => import('pages/RoomPage/WaitingRoomPage.vue'),
    },
    //연극 완료 페이지
    {
        path: '/end',
        component: () => import('pages/EndPage/EndPage.vue'),
    },
];

export default routes;
