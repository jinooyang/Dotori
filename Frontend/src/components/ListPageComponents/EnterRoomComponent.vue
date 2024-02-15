<script setup>
  import {ref} from 'vue';
  const { room } = defineProps(['room']);
  const dialog = ref('true');
  const isHovered = ref(false);
</script>

<template>
  <article class="room" @mouseover="isHovered = true" @mouseleave="isHovered = false">
    <div
      :style="{
        background: isHovered ? 'rgba(218, 201, 157, 0.87)' : 'transparent',
        borderRadius: '8px', // 책 모양을 위한 값
        border: 'none', // 테두리 제거
        boxShadow: '0px 2px 4px rgba(0, 0, 0, 0.1)' // 그림자 효과 추가
      }"
      class="q-pa-xs"
    >
    <div :style="{ background: isHovered ? 'white' : 'transparent', borderRadius: '8px' }" class='q-pa-xs'>
      <div style='background: white; border-radius: 20px; position: relative' class='q-pa-xs'>
        <q-img
          :ratio='2/1'
          :src="room.book.bookImg"
          style='border-radius: 15px'
        />

        <span class="on_now_tag npsfont" v-if="room.isRecording">연극 중</span>
        <span class="on_join_tag npsfont" v-else-if="room.joinCnt < room.limitCnt">대기 중</span>
        <span class="on_limit_tag npsfont" v-else>참여 불가</span>

        <hr style='border: #C7A96E 1px solid' />
        <div class='row q-mt-sm q-pa-sm flex justify-center items-center'
             style='background: white; border-radius: 20px'>
          <div class='col-8'>
            <div class=' npsfont text-h6 ellipsis'>
              {{ room.title }}
            </div>
<!--            <div class='npsfont'>-->
<!--              {{ room.book.title }}-->
<!--            </div>-->
            <div class='flex justify-start'>
              <div v-if="room.isPublic" class='npsfont'>
                공개 &nbsp&nbsp
              </div>
              <div v-else class='npsfont secret'>
                비공개 &nbsp&nbsp
              </div>
              <div class='npsfont'>
                인원 : {{ room.joinCnt }}/{{ room.limitCnt }}
              </div>
            </div>
          </div>
          <div class='col-4'>
            <div class='enter q-pa-sm flex justify-end items-center align-items: flex-end'>
              <q-btn flat @click='dialog = true' style='color: #C7A96E'
                     class='npsfont q-ma-none q-pa-none text-h6 '>입장하기
              </q-btn>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  </article>
</template>

<style scoped>

  .on_join_tag {
    position: absolute;
    top: 150px;
    right: 15px;
    font-size: 14px;
    color: white;
    padding: 2px 10px;
    margin-left: -7px;
    font-weight: 500;
    background-color: rgba(47, 187, 66, 0.95);
    border-radius: 20px;
  }
  .on_limit_tag {
    position: absolute;
    top: 150px;
    right: 15px;
    font-size: 14px;
    color: white;
    padding: 2px 10px;
    margin-left: -7px;
    font-weight: 500;
    background-color: rgba(248, 52, 80, 0.97);
    border-radius: 20px;
  }
  .on_now_tag{
    position: absolute;
    top: 150px;
    right: 15px;
    font-size: 14px;
    color: white;
    padding: 2px 10px;
    margin-left: -7px;
    font-weight: 500;
    background-color: rgba(248, 52, 80, 0.97);
    border-radius: 20px;
  }
  .on_now_tag:after {
    content: "";
    display: inline-block;
    width: 10px;
    height: 10px;
    background-color: white;
    border-radius: 50%;
    margin-left: 3px;
    -webkit-animation:blink 1s ease-in-out infinite alternate;
    -moz-animation:blink 1s ease-in-out infinite alternate;
    animation:blink 1s ease-in-out infinite alternate;
  }
  -webkit-keyframes blink{
    0% {opacity:0;}
    100% {opacity:1;}
  }
  @-moz-keyframes blink{
    0% {opacity:0;}
    100% {opacity:1;}
  }
  @keyframes blink{
    0% {opacity:0;}
    100% {opacity:1;}
  }

 .enter{
   position: absolute;
   top: 160px;
   right: 10px;
 }

.room:hover {
  transform: scale(1.0);
  transition: transform 0.5s ease;
}

.secret {
  color: red;
}
</style>
