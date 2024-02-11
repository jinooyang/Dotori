<template>
<!--  <div class="q-pa-md row items-start q-gutter-md">-->
<!--    <q-card class="my-card">-->
<!--      <img src="https://cdn.quasar.dev/img/parallax1.jpg">-->
<!--      <div class="text-center">{{ role }}</div>-->
<!--    </q-card>-->
<!--  </div>-->


  <div style="width: 116px;height: 116px; border-radius: 50%; border: #C7A96E 5px solid; padding: 3px;background: white;"
       class="q-ma-sm flex justify-center items-center relative-position">
    <img :src="props.role.maskThumbnailPath" width="100%" style="width:100px;height:100px;border-radius: 50%;object-fit: contain">
    <q-btn unelevated rounded :label="props.role.name" class="absolute-bottom my-avatar-btn"></q-btn>
  </div>
</template>

<script setup>
  const props = defineProps({role: Object});

</script>

<style scoped>
  .my-card{
    width: 100%;
    max-width: 100px;
    color: black;
  }
  .my-avatar-btn {
    background-color: white;

    font-family: "NPSfontBold";
    color: black;
    border: 3px solid #C7A96E;
    transform: translate(0,20%);
  }

</style>
