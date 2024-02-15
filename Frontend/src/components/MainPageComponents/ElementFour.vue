<template>
  <!--  <hr style='border: solid yellow 3px' />-->
  <div class='row'>

    <h3 class='npsfont q-mx-lg q-mt-lg q-mb-none col-10 offset-2' style='color: #282828; padding-bottom: 20px'>도토리는 어떻게 이용하나요?</h3>
    <!--    <h4 class='npsfont q-my-none'>역할에 맞는 수많은 3D 아바타를 통해 아이들의 창의력과 집중력을 향상시킵니다</h4>-->
    <div class="row col-10 offset-2">
    <q-card
      class="my-card text-white col-2"
    >
      <q-card-section>
        <div class="text-h6 text-black npsfont q-ma-md">1. 방을 만들어요.</div>
        <div class="text-subtitle2 text-black npsfont">원하는 책을 고르고, 방을 만들어요. 비밀 방도 만들 수 있어요!</div>
      </q-card-section>
      <q-card-section class="q-pt-none text-black npsfont">

      </q-card-section>
    </q-card>
      <q-card
        class="my-card text-white col-2"
      >
        <q-card-section>
          <div class="text-h6 text-black npsfont q-ma-md">2. 원하는 역할을 선택해요.</div>
          <div class="text-subtitle2 text-black npsfont">친구들과 채팅을 통해 이야기를 나누며, 각자 원하는 역할을 선택해요.</div>
        </q-card-section>
        <q-card-section class="q-pt-none text-black npsfont">

        </q-card-section>
      </q-card>
      <q-card
        class="my-card text-white col-2"
      >
        <q-card-section>
          <div class="text-h6 text-black npsfont q-ma-md">3. 연극을 녹화해요.</div>
          <div class="text-subtitle2 text-black npsfont">자신의 차례가 되면 동화 속 주인공이 되어 말하고, 연극을 녹화해요.</div>
        </q-card-section>
        <q-card-section class="q-pt-none text-black npsfont">

        </q-card-section>
      </q-card>
      <q-card
        class="my-card text-white col-2"
      >
        <q-card-section>
          <div class="text-h6 text-black npsfont q-ma-md">4. 완성된 연극 영상을 확인해요.</div>
          <div class="text-subtitle2 text-black npsfont">녹화가 종료되면, 마이페이지로 이동해 찍은 영상을 확인할 수 있어요.</div>
        </q-card-section>
        <q-card-section class="q-pt-none text-black npsfont">

        </q-card-section>
      </q-card>
    </div>
  </div>
  <!--  <hr style='border: solid yellow 3px' />-->
</template>

<script setup>

</script>

<style scoped>
  .my-card {
    width: 100%;
    max-width: 230px;
    height: 100%;
    max-height: 220px;
    margin: 15px;
    border-radius: 30px;

  }
  .my-card:nth-child(odd) {
    background-color: rgba(218, 201, 157, 0.8);
    box-shadow: 5px -5px 5px rgba(218, 201, 157, 0.87);
  }
  .my-card:nth-child(even) {
    background-color: rgb(197, 188, 170, 0.8);
    box-shadow: 5px -5px 5px rgba(189, 172, 157, 0.78);
  }
  .my-card:hover {
    //transform: scale(1.2); /* 1.1 배 확대 */
    //transition: transform 0.3s ease;
  }
</style>
