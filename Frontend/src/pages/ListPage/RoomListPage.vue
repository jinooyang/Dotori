<template>
  <q-page class="custom-padding">
    <headerbooklist/>
    <div class='row q-mb-md'>
      <div class='search row flex justify-center items-center' style='width: 100%;'>
        <q-input
          class=''
          standout rounded dense placeholder='검색'
          bg-color='white'
          style='width: 50%; border: rgba(218, 201, 157, 0.87) solid 3.5px; border-radius: 50px;'
          v-model="searchQuery"
          @keyup.enter="search"
        >
        </q-input>
        <q-btn
          class=''
          icon='search'
          round
          size='lg'
          flat
          unelevated
          style='color: #C7A96E; font-weight: bolder'
          @click="search"
        />
      </div>
    </div>

    <q-infinite-scroll @load="onLoad" :offset="250">
      <div class='row q-col-gutter-x-md q-col-gutter-y-md'>
        <div v-for='room in displayedRooms' :key='room.roomId' class='room-component col-12 col-sm-6 col-md-4 col-lg-3 q-pa-md'>
          <EnterRoomComponent :room='room' @click="() => enterRoom(room)"></EnterRoomComponent>
        </div>
      </div>
      <template v-slot:loading>
        <div class="row justify-center q-my-md">
          <q-spinner-dots color="positive" size="40px" />
        </div>
      </template>
    </q-infinite-scroll>

    <q-dialog v-model="showPasswordModal" persistent>
      <q-card style="min-width: 350px">
        <q-card-section>
          <div class="text-h6 npsfont">비밀번호 확인</div>
        </q-card-section>

        <q-card-section class="q-pt-none npsfont" >
          <q-input dense color="positive" v-model="password" type="password" label="비밀번호" autofocus @keyup.enter="prompt = false" />
        </q-card-section>

        <q-card-section class="npsfont" v-if="!isPasswordCorrect" style="padding-left: 16px; padding-top: 0; padding-bottom: 0">
          <span style="color: red">비밀번호가 일치하지 않습니다.</span>
        </q-card-section>

        <q-card-actions align="right" class="npsfont" >
          <q-btn flat label="Cancel"  @click="cancelPasswordCheck" />
          <q-btn flat label="Ok" @click="checkPassword" />
        </q-card-actions>
      </q-card>
    </q-dialog>

  </q-page>
</template>

<script>
  import EnterRoomComponent from 'components/ListPageComponents/EnterRoomComponent.vue';
  import {storeToRefs} from 'pinia';
  import {onMounted, ref} from 'vue';
  import {useRouter} from 'vue-router';
  import {useOpenViduStore} from 'stores/openvidu';
  import {localAxios} from 'src/axios/http-commons';
  import Headerbooklist from 'components/CommonComponents/Headerbooklist.vue';

  export default {
    components: {Headerbooklist, EnterRoomComponent},
    setup() {
      const axios = localAxios();
      const router = useRouter();
      const openViduStore = useOpenViduStore();
      const {roomInfo, roomId} = storeToRefs(openViduStore);
      const {getConnectionToken, connectToOpenVidu, addRoomMember} = openViduStore;

      const rooms = ref([]);
      const displayedRooms = ref([]);
      const loading = ref(false);

      const showPasswordModal = ref(false); // 모달 표시 여부
      const password = ref(''); // 입력된 비밀번호
      const isPasswordCorrect = ref(true);
      let room = null;

      const searchQuery = ref('');

      const search = () => {
        displayedRooms.value = rooms.value.filter(room => {
          return room.title.includes(searchQuery.value) || room.book.title.includes(searchQuery.value);
        });
      };

      // 비밀번호 확인 취소
      const cancelPasswordCheck = () => {
        showPasswordModal.value = false;
        password.value = '';
      };

      // 비밀번호 확인
      const checkPassword = () => {
        const enteredPassword = password.value; // 사용자가 입력한 비밀번호

        if (enteredPassword === room.password) {
          proceedToRoom(room);
        } else {
          isPasswordCorrect.value = false;
          password.value = '';
        }
      };

      const moveWaitingRoom = (room) => {
        roomId.value = room.roomId;
        roomInfo.value = room;
        router.push('/room');
      };

      onMounted(() => {
        fetchRooms();
        window.addEventListener('scroll', handleScroll);
      });

      // 방 목록 정보를 불러온다.
      const fetchRooms = async () => {
        try {
          const response = await axios.get('/api/rooms', {withCredentials: true});
          console.log('API Response:', response);
          rooms.value = response.data;
          displayedRooms.value = rooms.value.slice(0, 12);
        } catch (error) {
          console.error('Error fetching rooms:', error);
        }
      };

      const enterRoom = (selectedRoom) => {
        room = selectedRoom;
        if (!room.isPublic) {
          isPasswordCorrect.value = true; // 모달 열 때마다 초기화
          showPasswordModal.value = true; // 모달 열기
        } else {
          proceedToRoom(room);
        }
      };

      // 비밀번호 확인 후 방으로 진입
      const proceedToRoom = (room) => {
        getConnectionToken(room)
          .then(() => {
            connectToOpenVidu()
              .then(() => {
                addRoomMember(room.book)
                  .then(() => {
                    openViduStore.roomId = room.roomId;
                    moveWaitingRoom(room);
                  })
                  .catch((error) => {
                    console.error('참여 인원 갱신 중 에러 발생 : ' + error);
                  });
              })
              .catch((error) => {
                console.error('ov에 연결 중 에러 발생 : ' + error);
              });
          });
      };

      const handleScroll = () => {
        const scrollY = window.scrollY;
        const windowHeight = window.innerHeight;
        const documentHeight = document.body.scrollHeight;

        if (scrollY + windowHeight >= documentHeight && !loading.value) {
          loadMoreRooms();
        }
      };

      const loadMoreRooms = async () => {
        loading.value = true;
        setTimeout(() => {
          try {
            const startIndex = displayedRooms.value.length;
            const endIndex = startIndex + 12;
            const newRooms = rooms.value.slice(startIndex, endIndex);
            displayedRooms.value = [...displayedRooms.value, ...newRooms];
          } catch (error) {
            console.error('Error loading more rooms:', error);
          } finally {
            loading.value = false;
          }
        }, 1000); // 2초의 지연 추가
      };

      return {
        isPasswordCorrect,
        showPasswordModal,
        password,
        cancelPasswordCheck,
        checkPassword,
        rooms,
        moveWaitingRoom,
        enterRoom,
        displayedRooms,
        loading,
        searchQuery,
        search
      };
    },
  };
</script>

<style lang='scss' scoped>
  .custom-padding {
    padding-left: 30px; /* 왼쪽 패딩 크기 조정 */
    padding-right: 30px; /* 오른쪽 패딩 크기 조정 */
  }

  .room-component:hover {
    transform: scale(1.1); /* 1.1 배 확대 */
    transition: transform 0.3s ease;
  }
</style>
