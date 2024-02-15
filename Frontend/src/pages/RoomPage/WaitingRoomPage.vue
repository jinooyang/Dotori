<template>
  <Header/>
  <div class='row'>
    <div class='col-10 offset-1'>
      <div class='row'>
        <RoomTitle :roomInfo='roomInfo'></RoomTitle>
      </div>
      <div class='row'>
        <div class='col-8 q-pt-sm q-pl-sm q-pb-sm' >
          <PlayerList></PlayerList>
        </div>
        <div class='col-4 q-pa-sm '>
          <BookInfo :bookInfo='bookDetail.book'></BookInfo>
        </div>
      </div>
      <div class='row'>
        <div class='col-8 q-pl-sm q-pb-sm' style='height: 210px'>
          <RoomChat :playerList='playerList' :memberId='memberId'></RoomChat>
        </div>
        <div class='col-4 q-pl-sm q-pr-sm q-pb-sm'>
          <StartReady></StartReady>
        </div>
      </div>
    </div>
  </div>
</template>
<script setup>
  import Header from 'components/CommonComponents/Header.vue';
  import PlayerList from 'components/RoomPageComponents/PlayerList.vue';
  import BookInfo from 'components/RoomPageComponents/BookInfo.vue';
  import StartReady from 'components/RoomPageComponents/StartReady.vue';
  import RoomChat from 'components/RoomPageComponents/RoomChat.vue';
  import RoomTitle from 'components/RoomPageComponents/RoomTitle.vue';
  import {onMounted, ref} from 'vue';
  import {useOpenViduStore} from 'stores/openvidu';
  import {storeToRefs} from 'pinia';

  const openViduStore = useOpenViduStore();
  const {memberInfo,roomInfo,playerList,isHost,memberId,bookDetail} = storeToRefs(openViduStore);
  const {session} = openViduStore;

  const props = defineProps({memberId:Object});

  const sendingIncomingData = ref({
    player: null,
  });

  const sendingPlayerData = ref({
    playerList: null,
    roleList: null,
  });

  const sendIncomingInfoToOpenVidu = () => {
    return new Promise((resolve, reject) => {
      session.signal({
        data: JSON.stringify(sendingIncomingData.value),
        to: [],
        type: 'signal:give-playerList',
      })
        .then(() => {
          resolve('플레이어가 들어왔음');
        })
        .catch(error => {
          reject(error);
        });
    });
  };

  const sendPlayerInfoToOpenVidu = () => {
    return new Promise((resolve, reject) => {
      session.signal({
        data: JSON.stringify(sendingPlayerData.value),
        to: [],
        type: 'signal:player-incoming',
      })
        .then(() => {
          resolve('새로운 참여자 정보 전송 성공');
        })
        .catch(error => {
          reject(error);
        });
    });
  };

  // 방 참여자가 발생하면 방에 있던 모든 참여자들은 정보를 반영한다.
  session.on('signal:player-incoming', (event) => {
    const receivedData = JSON.parse(event.data);
    if (!isHost.value) {
      playerList.value = receivedData.playerList;
      bookDetail.value.roles = receivedData.roleList;   // 방에 들어오기 전 선택된 역할 정보 반영
      roomInfo.value.joinCnt = playerList.value.length;
    }
  });

  // 방 참여자가 참여자 정보를 요청하면 방장은 참여자 정보를 전송한다.
  session.on('signal:give-playerList', (event) => {
    const receivedData = JSON.parse(event.data);
    if (isHost.value) {
      playerList.value.push(receivedData.player);
      sendingPlayerData.value.playerList = playerList.value;
      sendingPlayerData.value.roleList = bookDetail.value.roles;
      sendPlayerInfoToOpenVidu();
      roomInfo.value.joinCnt++;
    }
  });

  onMounted(() => {

    bookDetail.value.roles.forEach((role) => {
      role['selected'] = false;
    })

    const player = {
      name: memberInfo.value.nickName,
      memberId: memberId.value,
      profileImg: memberInfo.value.profileImg,
      roleName: '역할 선택하기',
      roleIndex: 5,
      readyState: false,
    };


    let check = true;
    playerList.value.forEach((user) => {
      if (user.memberId === player.memberId) {
        check = false;
      }
    })

    if (check) {
      if (isHost.value) {
        playerList.value.push(player);
      } else {
        sendingIncomingData.value.player = player;
        sendIncomingInfoToOpenVidu();
      }
    }

  })


</script>

<style scoped>
  @font-face {
    font-family: 'NPSfontBold';
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2310@1.0/NPSfontBold.woff2') format('woff2');
    font-weight: 700;
    font-style: normal;
  }

  .npsfont {
    font-family: 'NPSfontBold';
  }

</style>
