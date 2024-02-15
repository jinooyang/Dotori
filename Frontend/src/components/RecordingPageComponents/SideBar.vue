<template>
  <div class='' style='height: 210px'>
    <q-scroll-area
      :thumb-style='thumbStyle'
      :bar-style='barStyle'
      style='height: 210px; max-width: 100%;'
    >
      <div class='flex no-wrap'>
        <SideBarComponent v-for='scene in ovstore.bookDetail.scenes' :scene="scene" :cur-page='props.curPage' @moveToPage='moveToPage' />
      </div>
    </q-scroll-area>
  </div>
</template>
<script setup>
  import SideBarComponent from 'components/RecordingPageComponents/SideBarComponent.vue';
  import {onMounted, ref} from 'vue';
  import {useOpenViduStore} from 'stores/openvidu';
  const ovstore = useOpenViduStore();
  const allScenes = ref();

  const props = defineProps({curPage: Number, currentScene: Object});
  const emit = defineEmits(['moveToPage']);
  const moveToPage = (nextPage) => {
    // alert("move!");
    // props.curPage.value = nextPage;
    emit('moveToPage', nextPage);
  };
  const thumbStyle = {
    right: '1.5px',
    borderRadius: '5px',
    backgroundColor: 'rgba(218, 201, 157, 0.87)',
    width: '5px',
    opacity: 0.75,
  };

  const barStyle = {
    borderRadius: '9px',
    backgroundColor: '#ffffff',
    width: '8px',
    opacity: 0,
  };
</script>
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

  .scene-short-info-container {
    //border: black solid 1px;
  }

  .scene-number-container {

  }


  .scene-thumbnail-container {
    width: 100%;
  }


  .out-back {
    background: #C7A96E;
    border-radius: 15px;
  }

  .in-back {
    background: white;
    border-radius: 15px;
  }

  .white-background {
    background: white;
    border-radius: 15px;
    width: 100%;
    border: #6E4E1F dashed 2px
  }

  .scene-bordering {
    border-radius: 15px;
    border: #6E4E1F solid 3px
  }
</style>
