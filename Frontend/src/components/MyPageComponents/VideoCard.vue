<template>

  <div class="text-subtitle2 ellipsis" v-text="props.roomInfo.title"></div>
  <div class="text-subtitle2 ellipsis" v-text="props.roomInfo.date"></div>


</template>

<script setup>
  const props = defineProps({
    roomInfo: {
      profileImagePath: String,
      title: String,
      date: String,
      downloadLink: String,
    },
  });
</script>

<style lang="scss" scoped>
  .dotori-border {
    border-radius: $dotori-border-radius;
    background-color: #ebf686;


  }

  .card-info-border-bottom {
    border-radius: 0px 0px 20px 20px;

  }
</style>
<style>
  .dotori-border {
  }
</style>
