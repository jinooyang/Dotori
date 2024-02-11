<script setup>
  import {useRouter} from 'vue-router';
  import {useOpenViduStore} from 'stores/openvidu';
  import {localAxios} from 'src/axios/http-commons';

  const axiosInstance = localAxios();
  const ovstore = useOpenViduStore();

  const router = useRouter();
  const moveMyPage = () => {
    router.push('/my-page/info');
  };
  const moveLoginPage = () => {
    router.push('/login');
  };
  const moveMainPage = () => {
    router.push('/');
  };
  const logout = async () => {
    try {
      const response = await axiosInstance.post(
        '/api/members/logout',
      );
      console.log('로그아웃 성공:', response.data);

      router.push('/').then(() => {
        window.location.reload();
      });
    } catch (error) {
      console.error('오류:', error);
    }
  };
</script>
<script>
  window.onscroll = function() {
    scrollFunction();
  };

  function scrollFunction() {
    if (document.body.scrollTop > 830 || document.documentElement.scrollTop > 830) {
      console.log("DOWN");
      document.getElementById('mainPageHeader').classList.remove('onUp');
      document.getElementById('mainPageHeader').classList.add('onDown');
    } else {
      console.log("UP");
      document.getElementById('mainPageHeader').classList.remove('onDown');
      document.getElementById('mainPageHeader').classList.add('onUp');
    }

  }

</script>
<template>
  <div class='row header-bg q-pt-sm q-pb-sm'  id='mainPageHeader'>
    <!--    <div class="col-4 offset-0 flex justify-center items-center" style="cursor: pointer">-->
    <!--    </div>-->

    <!--페이지 위치-->
    <div class='col-8 offset-0 flex justify-center items-start'>
      <img src='../../assets/DotoriImages/dotorisq.png' style='cursor:pointer' alt='logo' width='30%'
           @click='moveMainPage' />
    </div>

    <!-- 마이페이지와 로그인-->
    <div class='col-2 flex items-center justify-end npsfont' v-if='ovstore.isLoggedIn'>
      <q-btn flat class='text-h7 q-ma-none' style='transform: translate(70px,0px)' color='brand' @click='moveMyPage'>
        <span class='text-border' style='color: black'>마이페이지</span>&nbsp&nbsp
        <svg
          xmlns='http://www.w3.org/2000/svg'
          height='18'
          width='28'
          viewBox='0 0 640 512'
        >
          <path
            fill='#C7A96E'
            d='M224 256A128 128 0 1 0 224 0a128 128 0 1 0 0 256zm-45.7 48C79.8 304 0 383.8 0 482.3C0 498.7 13.3 512 29.7 512H322.8c-3.1-8.8-3.7-18.4-1.4-27.8l15-60.1c2.8-11.3 8.6-21.5 16.8-29.7l40.3-40.3c-32.1-31-75.7-50.1-123.9-50.1H178.3zm435.5-68.3c-15.6-15.6-40.9-15.6-56.6 0l-29.4 29.4 71 71 29.4-29.4c15.6-15.6 15.6-40.9 0-56.6l-14.4-14.4zM375.9 417c-4.1 4.1-7 9.2-8.4 14.9l-15 60.1c-1.4 5.5 .2 11.2 4.2 15.2s9.7 5.6 15.2 4.2l60.1-15c5.6-1.4 10.8-4.3 14.9-8.4L576.1 358.7l-71-71L375.9 417z'
          />
        </svg>
      </q-btn>
    </div>


    <div
      class='col-2 flex items-center justify-start npsfont'
      v-if='ovstore.isLoggedIn'
    >
      <q-btn flat class='text-h7 q-ma-none' style='transform: translate(70px,0px)' color='brand' @click='logout'
      ><span class='text-border' style='color: black'>로그아웃</span>
        &nbsp&nbsp
        <svg
          xmlns='http://www.w3.org/2000/svg'
          height='22'
          width='22'
          viewBox='0 0 512 512'
        >
          <path
            fill='#C7A96E'
            d='M217.9 105.9L340.7 228.7c7.2 7.2 11.3 17.1 11.3 27.3s-4.1 20.1-11.3 27.3L217.9 406.1c-6.4 6.4-15 9.9-24 9.9c-18.7 0-33.9-15.2-33.9-33.9l0-62.1L32 320c-17.7 0-32-14.3-32-32l0-64c0-17.7 14.3-32 32-32l128 0 0-62.1c0-18.7 15.2-33.9 33.9-33.9c9 0 17.6 3.6 24 9.9zM352 416l64 0c17.7 0 32-14.3 32-32l0-256c0-17.7-14.3-32-32-32l-64 0c-17.7 0-32-14.3-32-32s14.3-32 32-32l64 0c53 0 96 43 96 96l0 256c0 53-43 96-96 96l-64 0c-17.7 0-32-14.3-32-32s14.3-32 32-32z'
          />
        </svg>
      </q-btn>
    </div>

    <!-- 로그인-->
    <div
      class='col-4 flex items-center justify-center npsfont'
      v-if='!ovstore.isLoggedIn'
    >
      <q-btn
        flat
        class='text-h7 q-ma-none '
        style='transform: translate(160px,0px)'
        color='brand'
        @click='moveLoginPage'
      ><span class='text-border' style='color: black'>로그인</span>
        &nbsp&nbsp
        <svg
          xmlns='http://www.w3.org/2000/svg'
          height='22'
          width='22'
          viewBox='0 0 512 512'
        >
          <path
            fill='#C7A96E'
            d='M217.9 105.9L340.7 228.7c7.2 7.2 11.3 17.1 11.3 27.3s-4.1 20.1-11.3 27.3L217.9 406.1c-6.4 6.4-15 9.9-24 9.9c-18.7 0-33.9-15.2-33.9-33.9l0-62.1L32 320c-17.7 0-32-14.3-32-32l0-64c0-17.7 14.3-32 32-32l128 0 0-62.1c0-18.7 15.2-33.9 33.9-33.9c9 0 17.6 3.6 24 9.9zM352 416l64 0c17.7 0 32-14.3 32-32l0-256c0-17.7-14.3-32-32-32l-64 0c-17.7 0-32-14.3-32-32s14.3-32 32-32l64 0c53 0 96 43 96 96l0 256c0 53-43 96-96 96l-64 0c-17.7 0-32-14.3-32-32s14.3-32 32-32z'
          />
        </svg>
      </q-btn>
    </div>
  </div>
</template>

<style scoped>

  .onDown{
    background: white;
  }
  .onUp{
    background: transparent;
  }

  .text-border {
    text-shadow: -1px 0px white, 0px 1px white, 1px 0px white, 0px -1px white;
  }

  @font-face {
    font-family: 'NPSfontBold';
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2310@1.0/NPSfontBold.woff2') format('woff2');
    font-weight: 700;
    font-style: normal;
  }

  .npsfont {
    font-family: 'NPSfontBold';
  }

  .row.header-bg {
    position: fixed; /* 헤더를 화면 상단에 고정 */
    top: 0; /* 화면의 맨 위에 위치하도록 설정 */
    left: 0;
    width: 100%; /* 화면 전체 너비를 차지하도록 설정 */
    z-index: 999; /* 다른 요소 위에 나타나도록 설정 */
    //background: rgba(255, 255, 255, 0); /* 투명도 조절 가능한 백그라운드 색상 */
    /* 다른 스타일들 */
  }
</style>
