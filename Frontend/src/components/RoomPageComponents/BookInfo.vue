<script setup>
  const props = defineProps({bookInfo: Object});

</script>

<template>
  <div style='height: 100%' class='background-brown q-pa-sm'>

    <div style='height: 100%' class='background-yellow q-pa-sm '>
      <div class='column  flex justify-center items-center' style="width: 100%">
        <img :src='props.bookInfo.bookImg' class='bookimg' style="width: 100%;object-fit: fill;">
      </div>

      <div class=' column q-pa-sm background-white' style="overflow: auto;border-radius: 0px 0px 13px 13px">
        제목 : {{bookInfo.title}}<br />
        저자 :  {{bookInfo.author}}<br />
        필요 인원 : {{bookInfo.roleCnt}}<br />
        줄거리 : {{bookInfo.summary}}
        <br />
      </div>
    </div>

  </div>
</template>

<style scoped>
  .background-brown {
    background: rgba(218, 201, 157, 0.87);
    border-radius: 20px;

  }

  .background-yellow {
    background: white;
    border-radius: 15px;
  //border: dashed #cc765a 5px;
  }

  .background-white {
    background: white;
    height: 10em;

    border-radius: 20px 20px 20px 20px;
    font-family: NPSfontBold;
  //color : #a84d2f;

  }

  .bookimg {
    border-radius: 13px;
  //border: solid #cc765a 2px; height: 20em;
  }
</style>
