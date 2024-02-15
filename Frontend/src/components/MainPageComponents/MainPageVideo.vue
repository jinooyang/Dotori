<script setup>
  import { ref, onMounted } from 'vue';
  import { useRouter } from 'vue-router';
  import { useOpenViduStore } from 'stores/openvidu';
  import videoSrc1 from 'assets/MainPage/mainpage1.mp4'
  import videoSrc2 from 'assets/MainPage/mainpage2.mp4'

  const ovstore = useOpenViduStore();
  const router = useRouter();

  const autoplay = ref(true);
  const videos = ref([
    {
      src: videoSrc1,
      headText: '도토리랑 책 읽으러 갈래?',
      bottomText: '너도 나도 동화 속 주인공'
    },
    {
      src: videoSrc2,
      headText: '시작하자, 우리들의 이야기',
      bottomText: 'DO our sTORI, with DOTORI'
    }
  ]);

  const currentIndex = ref(0);
  const prevSlide = () => {
    currentIndex.value = (currentIndex.value - 1 + videos.value.length) % videos.value.length;
  };
  const nextSlide = () => {
    currentIndex.value = (currentIndex.value + 1) % videos.value.length;
  };

  const start = () => {
    if (ovstore.isLoggedIn) {
      router.push('/list/books');
    } else {
      router.push('/login-page');
    }
  };

  onMounted(() => {
    const video = document.querySelector('.video-slide video');
    video.addEventListener('ended', nextSlide);
  });
</script>

<template>
  <div class="video-container">
    <div class="video-carousel" >
      <div v-for="(video, index) in videos" :key="index" class="video-slide" :class="{ active: index === currentIndex }">
        <video autoplay loop muted :src="video.src" type="video/mp4"></video>
      </div>
    <div class="controls">
      <q-btn @click="prevSlide" round dense transition-prev="scale" class="prev-button" style="font-size: 6px;">
      </q-btn>
      &nbsp&nbsp
      <q-btn @click="nextSlide" round dense transition-next="scale" class="next-button" style="font-size: 6px; ">
      </q-btn>
    </div>
  </div>

    <div class='absolute-center custom-caption' v-if="videos.length > 0">
      <div class='npsfont text-h3 q-pa-sm text-center' style='color: white;'>{{ videos[currentIndex].headText }}</div>
      <div class='npsfont text-h5 q-pa-sm text-center' style='color: white;'>{{ videos[currentIndex].bottomText }}</div>
    </div>
  </div>
  <div class="npsfont btn-3d yellow" @click="start">시작하기</div>
</template>

<style lang='scss' scoped>
  .video-carousel {
    position: relative;
    width: 100%;
    height: 100%;
    overflow: hidden;
  }

  .video-slide {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    opacity: 0;
    transition: opacity 0.5s ease;
  }

  .video-slide.active {
    opacity: 1;
  }

  //.glossy {
  //  bottom: 120px; /* 하단으로부터의 거리 */
  //  left: 50%; /* 가운데 정렬을 위해 왼쪽 위치를 50%로 지정 */
  //}

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

  .controls {
    position: absolute;
    bottom: 230px;
    left: 50.5%;
    transform: translateX(-50%);
  }

  .prev-button,
  .next-button {
    margin: 0 5px;
    background-color: rgba(255, 255, 255, 0.7);
    color: black; /* 버튼 내부 텍스트의 색상을 지정합니다. */
  }
</style>

<style scoped>
  /* 3D Button */
  .btn-3d {
    z-index: 9999;
    cursor: pointer;
    position: fixed;
    width: 230px;
    height: 65px;
    bottom: 100px; /* 하단으로부터의 거리 */
    left: 50%; /* 가운데 정렬을 위해 왼쪽 위치를 50%로 지정 */
    transform: translateX(-50%);
    display: inline-block;
    font-size: 20px;
    padding: 20px 60px;
    color: #191919;
    margin: 20px 10px 10px;
    border-radius: 300px;
    text-align: center;
    transition: top .01s linear;
    text-shadow: 0 1px 0 rgba(0,0,0,0.15);
  }
  .btn-3d.yellow:hover {
    background-color: #fae061;
  }

  .btn-3d.yellow {
    background-color: #ffec6b;
    box-shadow: 0 0 0 1px #F0D264 inset,
    0 0 0 1px rgb(197, 188, 170) inset,
    0 3px 0 0 rgba(255, 238, 141, 0.7),
    0 8px 8px 0 rgba(0,0,0,0.5);
  }
  .btn-3d.yellow:active {
    box-shadow: 0 0 0 1px #ffec6b inset;
  }

</style>
