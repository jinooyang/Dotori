<script setup>
  import {useRouter} from 'vue-router';
  import {ref, watch} from 'vue';
  import {useOpenViduStore} from 'stores/openvidu';
  import {storeToRefs} from 'pinia';

  const router = useRouter();
  const btnValue = ref(false);
  const openViduStore = useOpenViduStore();
  const {bookDetail, playerList, isHost, roomInfo, memberId, myRole} = storeToRefs(openViduStore);
  const {session, updateRoom} = openViduStore;
  const canMoveWaitingRoom = ref(false);

  watch(canMoveWaitingRoom, (newVal, oldVal) => {
    if (newVal) {
      moveRecording();
    }
  });

  const checkRole = () => {
    const player = playerList.value.find(user => user.memberId === memberId.value);
    return player.roleIndex !== 5;
  }

  const updateState = () => {
    if (!checkRole()) {
      alert('역할을 선택해주세요!');
      return;
    }
    const player = playerList.value.find(user => user.memberId === memberId.value);
    if (player) {
      player.readyState = true;
      btnValue.value = true;
      sendingReadyData.value.playerList = playerList.value;
      sendReadyInfoToOpenVidu();
      alert('곧 시작합니다. 잠시만 기다려주세요!');
    }
  };

  const checkReadyState = () => {
    if (!checkRole()) {
      alert('역할을 선택해주세요!');
      return;
    }

    let readyCnt = 0;
    playerList.value.forEach((user) => {
      if (user.memberId === memberId.value) user.readyState = true;
      if (user.readyState) readyCnt++;
    });

    if (readyCnt === playerList.value.length) {
      updateRoom(true)
        .then(() => {
          sendMoveInfoToOpenVidu();
          canMoveWaitingRoom.value = true;
        })
        .catch((error) => {
          console.error(error);
        });
    } else {
      alert('모든 친구들이 준비할 때까지 기다려주세요!');
    }
  };
  const moveRecording = () => {
    playerList.value.forEach((user) => {
      if (user.memberId === memberId.value) {
        myRole.value = bookDetail.value.roles[user.roleIndex].roleId;
      }
    });
    router.push('/recording');
  };

  const sendingReadyData = ref({
    playerList: null,
  });

  const sendReadyInfoToOpenVidu = () => {
    return new Promise((resolve, reject) => {
      session.signal({
        data: JSON.stringify(sendingReadyData.value),
        to: [],
        type: 'signal:update-ready',
      })
        .then(() => {
          resolve('준비 상태 전송 성공');

        })
        .catch(error => {
          reject(error);
        });
    });
  };

  const sendMoveInfoToOpenVidu = () => {
    return new Promise((resolve, reject) => {
      session.signal({
        data: null,
        to: [],
        type: 'signal:move-recording',
      })
        .then(() => {
          resolve('녹화방 이동 정보 전송 성공');
        })
        .catch(error => {
          reject(error);
        });
    });
  };

  // 방 참여자의 준비 상태를 반영한다.
  session.on('signal:update-ready', (event) => {
    const receivedData = JSON.parse(event.data);
    playerList.value = receivedData.playerList;
  });

  // 녹화방으로 이동하라는 이벤트를 수신하면 방 참여자들은 모두 녹화방으로 이동한다.
  session.on('signal:move-recording', (event) => {
    roomInfo.value.isRecording = true;
    canMoveWaitingRoom.value = true;
  });


</script>

<template>
  <div style='height: 100%' class='background-green q-pa-sm'>

    <div
      style='
      height: 100%;
      display: flex;
      flex-direction: column;
      justify-content: center;
      '
      class='background-yellow q-pa-sm'
    >
      <q-btn unelevated class='start-btn' @click='updateState' v-if="!isHost" :disable="btnValue">
        <svg xmlns='http://www.w3.org/2000/svg' height='48' width='54' viewBox='0 0 576 512'>
          <!--!Font Awesome Free 6.5.1 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 2024 Fonticons, Inc.-->
          <path fill='#FFD43B'
                d='M316.9 18C311.6 7 300.4 0 288.1 0s-23.4 7-28.8 18L195 150.3 51.4 171.5c-12 1.8-22 10.2-25.7 21.7s-.7 24.2 7.9 32.7L137.8 329 113.2 474.7c-2 12 3 24.2 12.9 31.3s23 8 33.8 2.3l128.3-68.5 128.3 68.5c10.8 5.7 23.9 4.9 33.8-2.3s14.9-19.3 12.9-31.3L438.5 329 542.7 225.9c8.6-8.5 11.7-21.2 7.9-32.7s-13.7-19.9-25.7-21.7L381.2 150.3 316.9 18z' />
        </svg>
        준비하기
        <svg xmlns='http://www.w3.org/2000/svg' height='48' width='54' viewBox='0 0 576 512'>
          <!--!Font Awesome Free 6.5.1 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 2024 Fonticons, Inc.-->
          <path fill='#FFD43B'
                d='M316.9 18C311.6 7 300.4 0 288.1 0s-23.4 7-28.8 18L195 150.3 51.4 171.5c-12 1.8-22 10.2-25.7 21.7s-.7 24.2 7.9 32.7L137.8 329 113.2 474.7c-2 12 3 24.2 12.9 31.3s23 8 33.8 2.3l128.3-68.5 128.3 68.5c10.8 5.7 23.9 4.9 33.8-2.3s14.9-19.3 12.9-31.3L438.5 329 542.7 225.9c8.6-8.5 11.7-21.2 7.9-32.7s-13.7-19.9-25.7-21.7L381.2 150.3 316.9 18z' />
        </svg>
      </q-btn>
      <q-btn unelevated class='start-btn' @click='checkReadyState' v-else>
        <svg xmlns='http://www.w3.org/2000/svg' height='48' width='54' viewBox='0 0 576 512'>
          <!--!Font Awesome Free 6.5.1 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 2024 Fonticons, Inc.-->
          <path fill='#FFD43B'
                d='M316.9 18C311.6 7 300.4 0 288.1 0s-23.4 7-28.8 18L195 150.3 51.4 171.5c-12 1.8-22 10.2-25.7 21.7s-.7 24.2 7.9 32.7L137.8 329 113.2 474.7c-2 12 3 24.2 12.9 31.3s23 8 33.8 2.3l128.3-68.5 128.3 68.5c10.8 5.7 23.9 4.9 33.8-2.3s14.9-19.3 12.9-31.3L438.5 329 542.7 225.9c8.6-8.5 11.7-21.2 7.9-32.7s-13.7-19.9-25.7-21.7L381.2 150.3 316.9 18z' />
        </svg>
        시작하기
        <svg xmlns='http://www.w3.org/2000/svg' height='48' width='54' viewBox='0 0 576 512'>
          <!--!Font Awesome Free 6.5.1 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license/free Copyright 2024 Fonticons, Inc.-->
          <path fill='#FFD43B'
                d='M316.9 18C311.6 7 300.4 0 288.1 0s-23.4 7-28.8 18L195 150.3 51.4 171.5c-12 1.8-22 10.2-25.7 21.7s-.7 24.2 7.9 32.7L137.8 329 113.2 474.7c-2 12 3 24.2 12.9 31.3s23 8 33.8 2.3l128.3-68.5 128.3 68.5c10.8 5.7 23.9 4.9 33.8-2.3s14.9-19.3 12.9-31.3L438.5 329 542.7 225.9c8.6-8.5 11.7-21.2 7.9-32.7s-13.7-19.9-25.7-21.7L381.2 150.3 316.9 18z' />
        </svg>
      </q-btn>
    </div>
  </div>
</template>

<style scoped>

  .start-btn {
    //background: #35daa0; //color: white; font-family: NPSfontBold;
    font-size: 3.5em;
    color: #6E4E1F;
    background: white;
    height: 100%;
    border-radius: 20px 20px 20px 20px;
    border: dashed #6E4E1F 5px;

  }

  .background-green {
    background: #C7A96E;
    border-radius: 20px 20px 20px 20px;

  }

  .background-yellow {
    background: white;
    border-radius: 20px 20px 20px 20px;
    //border: dashed #cc765a 5px;
  }

  .background-white {
    background: floralwhite;
    height: 260px;

    border-radius: 20px 20px 20px 20px;
    font-family: NPSfontBold;
    border: solid #cc765a 2px;

  }

  .bookimg {
    border-radius: 20px 20px 20px 20px;
    border: solid #cc765a 2px;
  }
</style>
