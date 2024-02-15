<template>
  <video autoplay id = "mytestID"/>
</template>

<script>

  export default {
    name: 'OvVideo',

    props: {
      streamManager: Object,
    },

    mounted () {
      this.streamManager.addVideoElement(this.$el);
    },
  };
</script>

<style scoped>

</style>
