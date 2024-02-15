const routes = [
  {
    path: '/',
    component: () => import('layouts/MainLayout.vue'),
  },
  {
    path: '/login',
    component: () => import('pages/LoginPage.vue'),
  },
  {
    path: '/modal',
    component: () => import('pages/RoomMakingModal2.vue'),
  },
  {
    path: '/signup',
    component: () => import('pages/SingupPage.vue'),
  },
  {
    path: '/kakaologin',
    component: () => import('pages/SocialLogin/KakaoLogin.vue'),
  },

  {
    path: '/my-page',
    component: () => import('layouts/MyPageLayout.vue'),
    children: [
      {
        path: 'info',
        component: () => import('pages/MyInfoPage.vue'),
      },
      {
        path: 'collection',
        component: () => import('pages/MyVideoCollectionPage.vue'),
      },
      {
        path: 'avatar',
        component: () => import('pages/MyAvatarPage.vue'),
      },
    ],
  },
  {
    path: '/room-recording',
    component: () => import('pages/RoomRecording.vue'),
  },
  {
    path: '/List',
    component: () => import('layouts/List/Index.vue'),
    children: [
      {path: '', component: () => import('pages/List/IndexPage.vue')},
    ],
  },
  {
    path: '/book',
    component: () => import('layouts/List/Index.vue'),
    children: [
      {path: '', component: () => import('pages/List/BookIndexPage.vue')},
    ],
  },
  {
    path: '/room',
    component: () => import('pages/RoomPage.vue'),
  },
  {
    path: '/roomroom',
    component: () => import('pages/RoomPage2.vue'),
  },
  {
    path: '/end',
    component: () => import('pages/EndPage.vue'),
  },
];

export default routes;
