<template>
  <div class='row'>
    <div class='col-10 offset-1'>
      <div class='body q-ma-sm q-pa-sm'>
        <!-- 책과 책 정보 row-->
        <div class='book row q-gutter-x-sm'>
          <!-- 왼쪽 칼럼   책 이미지 -->
          <div class='col-4 flex justify-center items-center q-pa-sm'
               style='border: 5px solid #C7A96E; border-radius: 20px;height: 500px;'>
            <img :src='bookDetail.book.bookImg' alt='책'
                 style='height:100%;width:100%;object-fit: contain;border-radius: 20px;'
            >
          </div>
          <!-- 오른쪽 칼럼-->
          <div class='book-info col-8 q-gutter-y-sm'>
            <!--            책 제목과 줄거리-->
            <div style='border: 5px solid #C7A96E; border-radius: 20px;height: 246px;overflow: auto' class='q-pa-sm'>
              <div class='text-h5'>제목 : {{ bookDetail.book.title }}</div>
              <div>저자 : {{ bookDetail.book.author }}</div>
              <hr />
              {{ bookDetail.book.summary }}
            </div>
            <!--            등장 인물-->
            <div style='border: 5px solid #C7A96E; border-radius: 20px;height: 246px' class='q-pa-sm'>
              <div class='text-h5'>역할 소개</div>
              <hr />
              <div class='flex no-wrap' style='overflow:auto;'>
                <Character :role='role' v-for='role in bookDetail.roles' />
              </div>
            </div>
          </div>
        </div>
        <!--방 새로 만들기-->
        <div class='row'>
          <div class='col q-mt-sm'>
            <q-card flat class='mycard room-input col-12' style='border-radius: 20px;border: 5px solid #C7A96E'>
              <div class='room-info-inner'>
                <q-card-section>
                  <div class='q-pa-none q-ma-none text-h5'>방을 직접 만들 수 있어요!</div>
                </q-card-section>
                <q-separator inset />
                <div class='row q-mb-sm q-mt-sm'>
                  <div class='col-8 offset-1'>
                    <q-input rounded outlined label='방 제목을 입력하세요!' v-model='roomName' />
                  </div>
                  <div class='col-3 flex justify-center'>
                    <q-checkbox keep-color v-model='isPrivate' label='비밀로 할래요!' color='cyan' />
                  </div>
                </div>
                <div class='row q-mb-sm' v-if='isPrivate'>
                  <div class='col-8 offset-1'>
                    <q-input rounded outlined label='방 비밀번호를 입력하세요!' type='password' v-model='roomPassword' />
                  </div>
                </div>
                <div class='row q-mb-sm'>
                  <div class='col-9 flex'>
                  </div>
                  <div class='col-3 flex justify-center'>
                    <q-btn unelevated color='my-brown' rounded label='방 만들기' @click='joinRoom'></q-btn>
                  </div>
                </div>

              </div>
            </q-card>
          </div>
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
        console.log('API Response:', response);
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

    if (roomPassword.value === null && isPrivate.value) {
      alert('비밀번호 입력 필수');
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
              .catch(()=> {
                $q.loading.hide();
                $q.notify({
                  color: 'white',
                  textColor: 'red-9',
                  message: '문제가 생겼어요! 다시 방을 만들어 볼까요?',
                  position: 'center',
                  timeout: 500,
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
            });
          });
      });
  };
</script>

<style scoped>

  .body {
    background-color: white;
  }

  .book, .room-input {
    display: flex;
    flex-direction: row;
    border-radius: 10px;
    font-family: 'NPSfontBold', sans-serif;
  }

  .book-info-inner, .room-info-inner {
  //border: dashed #cc765a 5px; border-radius: 20px;
  }

  .book-info {
    display: flex;
    flex: 1;
    flex-direction: column;
  }

  .book-story, .book-roles {
    width: 100%;
    color: black;
    border-radius: 20px;
    background-color: #C7A96E;
  }

  .role-info {
    display: flex;
  }

  .room-input {
    width: 100%;
    display: flex;
    border-radius: 20px;
    background-color: #C7A96E;
    flex-direction: column;
  }

  .room-input > div > q-input {
    margin: 100px;
  }

  .bg-my-brown {
    background: #C7A96E !important;
  }

  @font-face {
    font-family: 'NPSfontBold';
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2310@1.0/NPSfontBold.woff2') format('woff2');
    font-weight: 700;
    font-style: normal;
  }
</style>

<style lang='scss'>
  .mycard.q-card > div:last-child {
    //border-bottom: dashed #cc765a 5px !important;
    //border-top: dashed #cc765a 5px !important;
    background-color: #ffffff;
    height: 100%;
  }

</style>
