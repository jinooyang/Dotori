<script setup>
  import {useOpenViduStore} from 'stores/openvidu';
  import {storeToRefs} from 'pinia';

  const openViduStore = useOpenViduStore();
  const {roomInfo} = storeToRefs(openViduStore);
</script>

<template>
  <div class='row col  background-green q-pa-sm q-mb-none q-ml-sm q-mr-sm q-mt-sm'>
    <div class='row col npsfont background-yellow q-pa-sm q-ma-none justify-between'>
      <h5 class='q-ma-none q-pl-md'>
        <!-- {{ props.roomInfo.roomNumber }} -->
      </h5>
      <h5 class='q-ma-none'>
        {{ roomInfo.title }}
      </h5>
      <h5 class='q-ma-none q-pr-md'>
        <span v-if='roomInfo.isPublic'>공개방🔓</span>
        <span v-else>비공개방🔒</span>
      </h5></div>
  </div>
</template>

<style scoped>
  .npsfont {
    font-family: 'NPSfontBold';
  }

  .background-yellow {
    background: white;
    border-radius: 15px;
    //box-shadow: -3px -3px 3px rgba(218, 201, 157, 0.63) inset;
  //border: dashed #cc765a 5px;
  }

  .background-green {
    background: rgba(218, 201, 157, 0.87);
    border-radius: 20px;

  }

</style>
