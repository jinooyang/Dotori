<template>
  <div>
    <h1>hello</h1>
    <video ref="videoPlayer" autoplay></video>
  </div>
</template>

<script setup>
  import {ref, onMounted} from 'vue';

  const videoPlayer = ref(null);

  onMounted(() => {
    startVideo();
  });

  const startVideo = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({video: true});
      videoPlayer.value.srcObject = stream;
    } catch (error) {
      console.error('Error accessing camera:', error);
    }
  };
</script>

<style scoped>
  video {
    transform: scaleX(-1); /* Mirror the video horizontally */
  }
</style>
