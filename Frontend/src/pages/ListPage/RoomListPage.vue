<template>
  <q-page padding>
    <div class='row q-mb-md'>
      <div class='search row flex justify-center items-center' style='width: 100%;'>
        <q-input
          class=''
          standout rounded dense placeholder='검색'
          color='black' bg-color='white'
          style='width: 50%; border: #C7A96E solid 5px; border-radius: 50px; '
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
        />
      </div>
    </div>
    <div class='row q-col-gutter-x-md q-col-gutter-y-md'>
      <div v-for='room in rooms' :key='room.roomId' class='col-12 col-sm-6 col-md-4 col-lg-3 q-pa-md'>
        <EnterRoomComponent :room='room' @click="() => enterRoom(room)"></EnterRoomComponent>
      </div>
    </div>
  </q-page>
</template>

<script>
  import EnterRoomComponent from 'components/ListPageComponents/EnterRoomComponent.vue';
  import {storeToRefs} from 'pinia';
  import {onMounted, ref} from 'vue';
  import {useRouter} from 'vue-router';
  import {useOpenViduStore} from 'stores/openvidu';
  import {localAxios} from 'src/axios/http-commons';

  export default {
    components: {EnterRoomComponent},
    setup() {
      const axios = localAxios();
      const router = useRouter();
      const rooms = ref([]);
      const openViduStore = useOpenViduStore();
      const {roomInfo,roomId} = storeToRefs(openViduStore);
      const {getConnectionToken, connectToOpenVidu, addRoomMember} = openViduStore;

      const moveWaitingRoom = (room) => {
        roomId.value = room.roomId;
        roomInfo.value = room;
        router.push('/room');
      };

      onMounted(() => {
        fetchRooms();
      });

      // 방 목록 정보를 불러온다.
      const fetchRooms = async () => {
        try {
          const response = await axios.get('/api/rooms',{withCredentials: true});
          console.log('API Response:', response);
          rooms.value = response.data;
        } catch (error) {
          console.error('Error fetching rooms:', error);
        }
      };

      const enterRoom = (room) => {
        // 유저 방정보, 책정보 가지고 입장.
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

      return {
        rooms,
        moveWaitingRoom,
        enterRoom,
      };
    },
  };
</script>

<style lang='scss' scoped>
</style>
