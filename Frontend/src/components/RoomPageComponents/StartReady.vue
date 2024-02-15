<script setup>
  import {useRouter} from 'vue-router';
  import {ref, watch} from 'vue';
  import {useOpenViduStore} from 'stores/openvidu';
  import {storeToRefs} from 'pinia';
  import {useQuasar} from 'quasar';

  const $q = useQuasar();
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
      $q.notify({
        color: 'white',
        textColor: 'green-9',
        message: '역할을 선택해주세요!',
        position: 'center',
        timeout: 500,
        icon: 'mdi-alert-outline',
      });
      return;
    }
    const player = playerList.value.find(user => user.memberId === memberId.value);
    if (player) {
      player.readyState = true;
      sendingReadyData.value.playerList = playerList.value;
      sendReadyInfoToOpenVidu()
        .then(() => {
          btnValue.value = true;
          $q.notify({
            color: 'white',
            textColor: 'green-9',
            message: '곧 시작합니다! 잠시만 기다려주세요!',
            position: 'center',
            timeout: 500,
            icon: 'mdi-alert-circle-outline',
          });
        })
        .catch((error) => {
          player.readyState = false;
          $q.notify({
            color: 'white',
            textColor: 'red-9',
            message: '준비 실패! 다시 시도해주세요!',
            position: 'center',
            timeout: 500,
            icon: 'mdi-alert-circle-outline',
          });
        });

    }
  };

  const checkReadyState = () => {
    if (!checkRole()) {
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: '역할을 선택해주세요!',
        position: 'center',
        timeout: 500,
        icon: 'mdi-alert-outline',
      });
      return;
    }

    // 테스트 후 주석 풀어주세요 !!!!
    if (playerList.value.length < bookDetail.value.book.roleCnt) {
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: '더 많은 친구들이 필요해요!',
        position: 'center',
        timeout: 500,
        icon: 'mdi-human-capacity-increase',
      });
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
        })
        .catch((error) => {
          console.error(error);
        });
    } else {
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: '모든 친구들이 준비해야 시작할 수 있어요!',
        position: 'center',
        timeout: 500,
        icon: 'mdi-alert-outline',
      });
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
        준  비
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
        시  작
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
    background: rgba(218, 201, 157, 0.45);
    box-shadow: -4px -4px 4px rgba(218, 201, 157, 0.45) inset;
    height: 100%;
    border-radius: 13px;
    border: rgba(110, 78, 31, 0.62) 5px;

  }

  .background-green {
    background: rgba(218, 201, 157, 0.87);
    border-radius: 20px;

  }

  .background-yellow {
    background: white;
    border-radius: 15px;
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
