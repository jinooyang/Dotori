<script setup>
  import {ref} from 'vue';
  import {useRouter} from 'vue-router';
  import {useOpenViduStore} from 'stores/openvidu';

  const ovstore = useOpenViduStore();
  const router = useRouter();

  const autoplay = ref(true);
  const videoSrc = 'src/assets/MainPage/MAIN2.mp4';
  const headText = 'DO STORY I';
  const bottomText = '이야기와 하나되는 아이들';

  const start = () => {
    if (ovstore.isLoggedIn) {
      router.push('/list/books');
    } else {
      router.push('/login');
    }
  };
</script>

<template>
  <div class="video-container">
    <video autoplay loop muted>
      <source :src='videoSrc' type="video/mp4">
    </video>
  </div>
  <div class='absolute-center custom-caption'>
    <div class='npsfont text-h4 q-pa-sm text-center' style='color: white;'>{{ headText }}</div>
    <div class='npsfont text-h5 q-pa-sm text-center' style='color: white;'>{{ bottomText }}</div>
  </div>
  <q-btn class="glossy" rounded color="secondary" label="시작하기"
         style='z-index: 9999; color: black; width: 150px; height: 50px; background: rgba(255, 255, 255, 0)'
         @click="start"></q-btn>

</template>

<style lang='scss' scoped>
  .glossy {
    position: fixed;
    bottom: 120px; /* 하단으로부터의 거리 */
    left: 50%; /* 가운데 정렬을 위해 왼쪽 위치를 50%로 지정 */
    transform: translateX(-50%);
  }

  .video-container {
    width: 98.9vw; /* 뷰포트의 가로 크기 */
    height: 100vh; /* 뷰포트의 세로 크기 */
    overflow: hidden; /* 비디오가 부모 컨테이너를 벗어나지 않도록 함 */
  }

  video {
    width: 100%;
    height: 100%;
    object-fit: cover; /* 비디오를 컨테이너에 맞게 자동 조절 */
  }
</style>
