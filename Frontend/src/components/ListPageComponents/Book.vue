<template>
  <article class="book" @mouseover="isHovered = true" @mouseleave="isHovered = false">
    <div
      :style="{
        background: isHovered ? 'rgba(218, 201, 157, 0.87)' : 'transparent',
        borderRadius: '8px', // 책 모양을 위한 값
        border: 'none', // 테두리 제거
        boxShadow: '0px 2px 4px rgba(0, 0, 0, 0.1)' // 그림자 효과 추가
      }"
      class="q-pa-xs"
    >
      <div :style="{ background: isHovered ? 'white' : 'transparent', borderRadius: '8px' }" class="q-pa-xs">
        <q-img
          :ratio="9/9"
          :src="bookdetail.bookImg"
          style="border-radius: 8px"
        />
        <hr style="border: none" />
        <div
          class="row q-mt-xs q-pa-xs flex justify-center items-center"
          :style="{ background: isHovered ? 'white' : 'transparent' }"
        >
          <div class="col-7">
            <div class="npsfont text-h6 ellipsis">
              {{ bookdetail.title }}
            </div>
            <div class="npsfont">
              {{ bookdetail.author }}
            </div>
          </div>
          <div class="col-5">
            <div class="q-pa-sm flex justify-end items-center">
              <q-btn flat @click="dialog = true" style="color: #C7A96E" class="npsfont q-ma-none q-pa-none text-h6 ">
                방만들기
              </q-btn>
              <q-dialog v-model="dialog">
                <q-card style="width: 1200px; max-width: 80vw; height:800px;">
                    <NewRoomModal :bookmodal="bookdetail"></NewRoomModal>
                </q-card>
              </q-dialog>
            </div>
          </div>
        </div>
      </div>
    </div>
  </article>
</template>

<script setup>
  import { ref } from 'vue';
  import NewRoomModal from 'pages/ListPage/NewRoomModal.vue';

  const dialog = ref(false);
  const props = defineProps({ bookdetail: Object });
  const isHovered = ref(false);
</script>

<style scoped>
  .book:hover {
    transform: scale(1.1);
    transition: transform 0.3s ease;
  }
</style>
