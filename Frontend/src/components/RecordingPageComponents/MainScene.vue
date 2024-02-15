<script setup>

  import OvVideo from 'components/RecordingPageComponents/OvVideo.vue';
  import {useOpenViduStore} from 'stores/openvidu';
  import {ref} from 'vue';

  const ovstore = useOpenViduStore();
  const props = defineProps({curPage: Number, currentScene: Object});
  // const imagesrc = ref(ovstore.bookInfoList[props.curPage - 1].img);

</script>

<template>

  <div class='scene-info-container q-pa-sm relative-position borderbrown'
       >
    <div v-if="ovstore.onAir===1">
      <div class="absolute-top-left "
           style="z-index:10; width: 100px;height: 100px;border-top: white 5px solid; border-left:white 5px solid;margin:30px">
        <h4 class="q-ma-sm flex no-wrap" style="color: white">
          <q-icon name="mdi-circle" color="red"></q-icon>
          REC
        </h4>
      </div>
      <div class="absolute-top-right  "
           style="z-index:10; width: 100px;height: 100px;border-top: white 5px solid;border-right:white 5px solid;margin:30px"></div>
      <div class="absolute-bottom-left  "
           style="z-index:10; width: 100px;height: 100px;border-bottom: white 5px solid;border-left:white 5px solid;margin:30px"></div>
      <div class="absolute-bottom-right  "
           style="z-index:10; width: 100px;height: 100px;border-bottom: white 5px solid;border-right:white 5px solid;margin:30px"></div>
    </div>
    <div class=' ' style='height: 100%;border-radius: 15px'>
      <div class='scene-background-container relative-position'>
        <q-img
          class='q-pa-xs'
          :src='props.currentScene.backgroundImage'
          :ratio='16/9'
          style='height: 100%;border-radius: 21px; '
        />
        <div class='flex justify-center items-center absolute-bottom q-ma-none q-pa-none'>
          <div v-if='ovstore.mainStreamManager'>
            <ov-video style="" :stream-manager='ovstore.mainStreamManager'
                      :id='ovstore.mainStreamManager.stream.streamId' />
          </div>
          <div v-for='sub in ovstore.subscribers' :key='sub.stream.connection.connectionId'>
            <ov-video :stream-manager='sub'
                      :id='sub.stream.streamId' />
          </div>
        </div>
        <div id='canvasDiv'></div>
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


  .scene-info-container {
    height: 570px;
    //border-radius: 15px;

  }

  .borderbrown {
    border:rgba(218, 201, 157, 0.87) solid 6px;
      border-radius: 30px;
  }



  .scene-background-container {
    height: 100%;
  }

  .text-border {
    text-shadow: -1px 0px black, 0px 1px black, 1px 0px black, 0px -1px black;
  }

</style>
