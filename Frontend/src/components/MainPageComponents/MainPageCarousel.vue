<script setup>
  import { ref, onMounted, watchEffect } from 'vue';

  const slide = ref('first');
  //메인페이지 캐러셀 자동반복
  const autoplay = ref(true);
  const slides = ref([
    {
      img: 'src/assets/MyPageImages/karina.jpg',
      name: 'first',
      headText: '도토리에 오신것을 환영합니다',
      bottomText: '카리나!!!!',
    },
    {
      img: 'src/assets/MyPageImages/winter.png',
      name: 'second',
      headText: 'Welcome To Dotori Online',
      bottomText: '윈터!!!',
    },
    {
      img: 'src/assets/MyPageImages/iupic.jpg',
      name: 'third',
      headText: '나만의 이야기를 만들어보세요',
      bottomText: '아이유!!',
    }
  ]);
</script>

<template>
  <div class="carousel-container">
    <q-carousel
      navigation
      infinite
      :autoplay='autoplay'
      animated
      v-model='slide'
      height='500px'
    >
      <q-carousel-slide
        v-for='(slide, index) in slides'
        :key='index'
        :name='slide.name'
        :img-src='slide.img'
      >
        <div class='absolute-bottom custom-caption'>
          <div class='text-h2 npsfont q-pa-sm text-border'>{{ slide.headText }}</div>
          <div class='text-h3 npsfont q-pa-sm text-border'>{{ slide.bottomText }}</div>
        </div>
      </q-carousel-slide>
    </q-carousel>
  </div>
</template>

<style lang='scss' scoped>
  .carousel-container {
    width: 50%;
    margin: 20%;
  }

  .text-border {
    text-shadow: -1px 0px #C7A96E, 0px 1px #C7A96E, 1px 0px #C7A96E, 0px -1px #C7A96E;
  }
</style>
