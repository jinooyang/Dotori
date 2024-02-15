<template>
  <div style="position: relative;">
    <img :src="bookDetail.book.bookImg" alt="책" class="flex justify=center" style="height:100%; max-height: 360px; width:100%; object-fit: cover; filter: blur(20px);">
    <img :src="bookDetail.book.bookImg" alt="책" class="flex justify=center" style="position: absolute; top: 10%; left: 30%; height:85%; width:40%;">
    <q-btn style="position: absolute; top: 0; right: 0;" flat icon="close" color="black" v-close-popup />
  </div>
  <div class="row q-ma-sm">
    <div class="col-7">
      <div class='col-7 q-pa-lg'>
        <!--            책 제목과 줄거리-->
        <div style='height: 200px;overflow: auto' class='q-pa-sm npsfont'>
          <div class='text-h4 q-pa-sm'>{{ bookDetail.book.title }} <span class='text-h6'>{{ bookDetail.book.author }}</span></div>
          <hr />
          {{ bookDetail.book.summary }}
        </div>
        <!--            등장 인물-->
        <div style='height: 190px' class='q-pa-sm'>
          <div class='text-h5 npsfont'>역할 소개</div>
          <hr />
          <div class='flex no-wrap' style='overflow:auto;'>
            <Character :role='role' v-for='role in bookDetail.roles' />
          </div>
        </div>
      </div>
    </div>
    <!--방 새로 만들기-->
    <div class='col-5'>
      <div class='col-5 q-pa-lg'>
        <div style='height: 260px; overflow: auto' class='q-pa-sm npsfont'>
          <div class='text-h4 q-pa-sm'>친구들을 모아볼까요?</div>
          <hr />
          <div class='row q-ma-md'>
            <div class='col-9 offset-0'>
              <q-input rounded outlined label='방 제목을 입력하세요!' v-model='roomName' />
            </div>
            <div class='col-3 flex justify-center'>
              <q-checkbox keep-color v-model='isPrivate' label='🔒' color='cyan' />
            </div>
          </div>
          <div class='row q-ma-md' v-if='isPrivate'>
            <div class='col-9 offset-0'>
              <q-input rounded outlined label='방 비밀번호를 입력하세요!' type='password' v-model='roomPassword' />
            </div>
          </div>
        </div>
        <div class="col-5">
          <q-btn unelevated class='create-btn npsfont' @click='joinRoom'>
            <svg xmlns='http://www.w3.org/2000/svg' height='48' width='54' viewBox='0 0 576 512'>
              <!--!Font Awesome Free 6.5.1 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 2024 Fonticons, Inc.-->
              <path fill='#FFD43B'
                    d='M316.9 18C311.6 7 300.4 0 288.1 0s-23.4 7-28.8 18L195 150.3 51.4 171.5c-12 1.8-22 10.2-25.7 21.7s-.7 24.2 7.9 32.7L137.8 329 113.2 474.7c-2 12 3 24.2 12.9 31.3s23 8 33.8 2.3l128.3-68.5 128.3 68.5c10.8 5.7 23.9 4.9 33.8-2.3s14.9-19.3 12.9-31.3L438.5 329 542.7 225.9c8.6-8.5 11.7-21.2 7.9-32.7s-13.7-19.9-25.7-21.7L381.2 150.3 316.9 18z' />
            </svg>
            방 만들기
            <svg xmlns='http://www.w3.org/2000/svg' height='48' width='54' viewBox='0 0 576 512'>
              <!--!Font Awesome Free 6.5.1 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 2024 Fonticons, Inc.-->
              <path fill='#FFD43B'
                    d='M316.9 18C311.6 7 300.4 0 288.1 0s-23.4 7-28.8 18L195 150.3 51.4 171.5c-12 1.8-22 10.2-25.7 21.7s-.7 24.2 7.9 32.7L137.8 329 113.2 474.7c-2 12 3 24.2 12.9 31.3s23 8 33.8 2.3l128.3-68.5 128.3 68.5c10.8 5.7 23.9 4.9 33.8-2.3s14.9-19.3 12.9-31.3L438.5 329 542.7 225.9c8.6-8.5 11.7-21.2 7.9-32.7s-13.7-19.9-25.7-21.7L381.2 150.3 316.9 18z' />
            </svg>
          </q-btn>
        </div>
      </div>
    </div>
  </div>

</template>


<script setup>
  import Character from 'components/MyPageComponents/Character.vue';
  import {storeToRefs} from 'pinia';
  import {useRouter} from 'vue-router';
  import {useOpenViduStore} from 'stores/openvidu';
  import {onMounted, ref} from 'vue';
  import {QSpinnerHourglass, useQuasar} from 'quasar';
  import {localAxios} from 'src/axios/http-commons';

  const axios = localAxios();
  const $q = useQuasar();
  const router = useRouter();
  const props = defineProps({bookmodal: Object});
  const moveWaitingRoom = () => {
    isHost.value = true;
    router.push('/room');
  };

  const openViduStore = useOpenViduStore();
  const {roomInfo, bookDetail, minRole, isHost} = storeToRefs(openViduStore);
  const {createRoom, connectToOpenVidu, addRoomMember, memberInfo} = openViduStore;

  onMounted(() => {
    fetchBookRoles();
  });

  const fetchBookRoles = () => {
    return new Promise(async (resolve, reject) => {
      try {
        const response = await axios.get(`/api/books/${props.bookmodal.bookId}`, {withCredentials: true});
        bookDetail.value = response.data;
        resolve();
      } catch (error) {
        reject(error);
      }
    });
  };

  const roomName = ref(null);
  const roomPassword = ref(null);
  const isPrivate = ref(false);

  const components = {Character};
  const joinRoom = () => {

    if (roomName.value === null) {
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: '방 제목을 입력해주세요!',
        position: 'center',
        timeout: 500,
        icon: 'mdi-lock-alert-outline',
      });
      return;
    }

    if (roomPassword.value === null && isPrivate.value) {
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: '비밀번호를 입력해주세요!',
        position: 'center',
        timeout: 500,
        icon: 'mdi-lock-alert-outline',
      });
      return;
    }

    roomInfo.value.title = roomName.value;
    roomInfo.value.password = roomPassword.value;
    roomInfo.value.isPublic = !isPrivate.value;
    roomInfo.value.limitCnt = bookDetail.value.book.roleCnt;
    //방을 생성한 사람은 본인의 memberId를 hostId로 저장한다
    roomInfo.value.hostId = memberInfo.memberId;
    isHost.value = true;

    $q.loading.show({
      message: '방을 만들고 있어요! 잠시만 기다려주세요!',
      spinner: QSpinnerHourglass,
      boxClass: 'bg-grey-2 text-grey-9',
      spinnerColor: 'brown',
    });

    createRoom(props.bookmodal)
      .then(() => {
        connectToOpenVidu()
          .then(() => {
            addRoomMember(props.bookmodal)
              .then(() => {
                roomInfo.value.joinCnt++;
                moveWaitingRoom();
                $q.loading.hide();
              })
              .catch(() => {
                $q.loading.hide();
                $q.notify({
                  color: 'white',
                  textColor: 'red-9',
                  message: '문제가 생겼어요! 새로 고침 후, 다시 방을 만들어 볼까요?',
                  position: 'center',
                  timeout: 500,
                  icon: 'mdi-alert-outline',
                });
              });
          })
          .catch(() => {
            $q.loading.hide();
            $q.notify({
              color: 'white',
              textColor: 'red-9',
              message: '문제가 생겼어요! 새로 고침 후, 다시 방을 만들어 볼까요?',
              position: 'center',
              timeout: 500,
              icon: 'mdi-alert-outline',
            });
          });
      })
      .catch(() => {
        $q.loading.hide();
        $q.notify({
          color: 'white',
          textColor: 'red-9',
          message: '문제가 생겼어요! 다시 방을 만들어 볼까요?',
          position: 'center',
          timeout: 500,
          icon: 'mdi-alert-outline',
        });
        router.push('/list/books');
      });
  };
</script>

<style scoped>
  @font-face {
    font-family: 'NPSfontBold';
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2310@1.0/NPSfontBold.woff2') format('woff2');
    font-weight: 700;
    font-style: normal;
  }
</style>

<style lang='scss'>
  .create-btn {
    //background: #35daa0; //color: white; font-family: NPSfontBold;
    font-size: 3.5em;
    color: #6E4E1F;
    background: rgba(218, 201, 157, 0.45);
    box-shadow: -5px -5px 5px rgba(218, 201, 157, 0.45) inset;
    width: 100%;
    border-radius: 40px;
    border: rgba(110, 78, 31, 0.62) 5px;
  }

</style>
