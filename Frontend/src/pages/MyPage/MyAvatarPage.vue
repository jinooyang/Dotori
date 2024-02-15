<template>
  <q-page>
    <div class="text-h3 npsfont q-pl-lg">아바타</div>
    <hr class="q-my-md">
    <!--    <div class="container">-->
    <!--      <div class="one-row row q-gutter-y-lg">-->
    <!--        <div class="col-xs-12 col-sm-4 col-md-3 col-lg-2 flex justify-center items-center" v-for="i in 6"-->
    <!--             key="dummy.id">-->
    <!--          <div class="contents radius-border light-green-bg flex justify-center items-center avatar-frame-size">-->
    <!--            <img class="avatar-size dashed-border radius-border" src="https://cdn.quasar.dev/img/avatar.png">-->
    <!--          </div>-->
    <!--        </div>-->
    <!--      </div>-->
    <!--    </div>-->
    <div class=" flex">
      <div style="width: 220px;height: 220px; border-radius: 50%; border:#C7A96E 5px solid; padding: 3px;background: white;"
           class="q-ma-lg flex justify-center items-center relative-position" v-for="item in 13">
        <img src="../../assets/MyPageImages/pikachu.jpg" width="100%" style="width:200px;height:200px;border-radius: 50%;object-fit: contain">
        <q-btn unelevated rounded label="피카츄" class="absolute-bottom-right my-avatar-btn"></q-btn>
      </div>


    </div>

  </q-page>
</template>

<script setup>
  const dummyData = {};
  const plus = {};
</script>

<style lang="scss" scoped>
  .light-green-bg {
    background: $dotori-light-green;
  }

  .radius-border {
    border-radius: $dotori-border-radius;
  }

  .dashed-border {
    border: $dotori-dashed-border;
  }

  .avatar-frame-size {
    width: 150px;
    height: 150px;
  }

  .avatar-size {
    width: 110px;
    height: 110px;
  }

  .my-avatar-btn {
    background-color: #C7A96E;
    font-family: "NPSfontBold";
    color: white;
  }

</style>
