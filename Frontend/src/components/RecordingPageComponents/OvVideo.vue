<script setup>
  import {defineProps, onMounted, ref} from 'vue';

  const props = defineProps({streamManager: Object, id: String});

  const thisvideo = ref();
  onMounted(() => {
    thisvideo.value.setAttribute('id', props.id);
    console.log('props.id : ' + props.id);

    props.streamManager.addVideoElement(document.getElementById(props.id));
  });
</script>

<template>
  <video class='cusvid' autoplay ref='thisvideo' id='myovvideo' />
</template>

<style scoped>
  .cusvid {
    z-index: 2;
    width: 250px;

    //border-radius: 15px;

    //box-shadow: #C7A96E 0px 0px 3px 1px;
  }

</style>
