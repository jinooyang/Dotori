<script setup>
  import {useOpenViduStore} from 'stores/openvidu';
  import {ref} from 'vue';

  const ovstore = useOpenViduStore();
  const props = defineProps({currentScene: Object});


</script>

<template>
  <div class='scene-script-container npsfont col-8'>
    <div class='out-back q-pa-xs' style='height: 100%'>
      <div class='in-back q-pa-sm' style='height: 100%'>
        <div class='script-background q-pa-sm'>
          <h4 class='q-my-none q-mx-none text-center'>대본📃</h4>
          <!--          <h6 class="q-ml-none q-mt-sm q-mb-none">역할에 맞는 대본을 읽어보세요!</h6>-->
          <hr style='border: 2px dashed #6E4E1F' class='q-mb-md' />
          <div v-for='script in currentScene.scriptDto' class='role-script-container'>
            <p class='text-weight-bold q-ma-none'>{{ script.content }}</p>
            <br />
          </div>
          <br />

        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
  @font-face {
    font-family: 'NPSfontBold';
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2310@1.0/NPSfontBold.woff2') format('woff2');
    font-weight: 700;
    font-style: normal;
  }

  .npsfont {
    font-family: 'NPSfontBold';
  }


  .scene-script-container {
    height: 570px;
  //border: dimgrey solid 1px;
  //display: flex;
  //justify-content: center;
  //align-items: center;
  }

  .out-back {
    background: #C7A96E;
    //border-radius: 15px;
    padding: 6px;
  }

  .in-back {
  //background: #ffee9a;
    background: white;
    //border-radius: 15px;
  }


  .script-background {
    background: white;
    //border-radius: 15px;
    height: 100%;

  }

</style>
