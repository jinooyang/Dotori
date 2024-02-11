<template>
  <Header/>
<!--  <Header></Header>-->
  <!--  <div style="background: #d2fff7" class = "q-pa-lg row">-->
  <div class="q-pa-lg row">
    <div
         class="q-ma-lg q-pa-lg col-8 offset-2">
      <div class="row">
        <!--        <div class="col-2"></div>-->
        <div class="col-3 flex justify-center items-center q-pa-sm " v-for="item in 4" key=item>
          <div class="background-green flex items-center justify-center">
            <img class="q-ma-md" src="../../assets/DotoriImages/acorn_character_img.png" width="80%">
          </div>
        </div>
        <!--        <div class="col-2"></div>-->
      </div>

      <div class="row flex justify-center">
        <h2 class="npsfont q-mb-md">수고하셨습니다</h2>


      </div>
      <div class="row flex justify-center">
        <h4 class="npsfont q-mb-md q-mt-none">결과는 마이페이지에서 확인하세요!</h4>
      </div>
      <div class="row flex justify-center">
        <q-btn unelevated rounded color="my-brown" class="q-mx-sm" size="1.5em" label="홈으로" />
        <q-btn unelevated rounded color="my-brown" class="q-mx-sm" size="1.5em" label="마이페이지" />
      </div>
    </div>
  </div>
</template>
<script setup>
  import Header from 'components/CommonComponents/Header.vue';
</script>

<style scoped>
  .end-border {
    border: dashed 5px #C7A96E;
    background: white;
    border-radius: 20px
  }

  img {
    background: white;
    border-radius: 20px;
  }

  .background-green {
    background: #C7A96E;
    border-radius: 20px;

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

  .bg-my-brown {
    background: #C7A96E !important;
  }

</style>
