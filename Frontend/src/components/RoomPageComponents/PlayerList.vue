<template>
  <div class='player'>
    <div class='row q-pt-sm q-pl-sm' >
      <div v-for='player in 4' :key='player' class='col-6 text-h3  q-pb-sm q-pr-sm'
      >
        <div v-if='player <= playerList.length' >
          <!-- 플레이어가 있으면서 사용자의 프로필이 맞는 경우-->
          <div class='profile-background q-pa-sm' v-if='memberId === playerList[player-1].memberId'>
            <div class='dashed column items-center relative-position'>
              <div v-if='playerList[player-1].readyState'
                   class='absolute-top-right q-py-xs q-px-sm q-my-none npsfont q-ma-xs'
                   style='background: green;color: white;border-radius: 20px;font-size: small;line-height: 20px'><p
                class='q-ma-none'>준비</p>
              </div>
              <img :src='playerList[player - 1].profileImg' class='profile-pic q-mt-md' alt='user-profile-img'
                   style='object-fit: cover'>
              <h4 class='q-mt-sm q-mb-sm player-name text-center'>{{ playerList[player - 1].name }}</h4>
              <div class='row q-mt-none q-mb-sm'>
                <q-btn unelevated rounded color='my-brown btn-font' :disable='playerList[player-1].readyState'>
                  <q-menu fit anchor='bottom start' self='top left'>
                    <q-item v-for='(role, index) in bookDetail.roles' :key='role' :disable='role.selected' clickable
                            @click='toggleRole(player,index)'>
                      <q-item-section>{{ role.name }}</q-item-section>
                    </q-item>
                  </q-menu>
                  <div>{{ playerList[player - 1].roleName }}</div>
                </q-btn>
                <q-btn unelevated rounded color='my-brown q-ml-sm btn-font' v-if='playerList[player-1].roleIndex !== 5'
                       @click='cancelRole(player)' :disable='playerList[player-1].readyState'>
                  <div>취소</div>
                </q-btn>
              </div>
            </div>
          </div>
          <!-- 플레이어가 있으면서 사용자의 프로필이 아닌 경우-->
          <div class='profile-background q-pa-sm' v-else>
            <div class='dashed column items-center relative-position'>
              <div v-if='playerList[player-1].readyState'
                   class='absolute-top-right q-py-xs q-px-sm q-my-none npsfont q-ma-xs'
                   style='background: green;color: white;border-radius: 20px;font-size: small;line-height: 20px'><p
                class='q-ma-none'>준비</p>
              </div>
              <img :src='playerList[player - 1].profileImg' class='profile-pic q-mr-md q-mt-sm' alt='user-profile-img'
                   style='object-fit: cover'>
              <h4 class='q-mr-md q-mt-md q-mb-sm player-name'>{{ playerList[player - 1].name }}</h4>
              <div class='row q-mt-none q-mb-sm'>
                <q-btn unelevated rounded color='my-brown q-mr-sm btn-font'
                       :disable='playerList[player-1].memberId !== memberId'>
                  <q-menu fit anchor='bottom start' self='top left'>
                    <q-item clickable>
                      <q-item-section>토끼</q-item-section>
                    </q-item>
                    <q-item clickable>
                      <q-item-section>거북이</q-item-section>
                    </q-item>
                  </q-menu>
                  <div>{{ playerList[player - 1].roleName }}</div>
                </q-btn>
                <q-btn unelevated rounded color='my-brown q-ml-sm btn-font' style='display: none'>
                  <div>취소</div>
                </q-btn>
              </div>
            </div>
          </div>
        </div>
        <!-- 플레이어가 없는 경우 -->
        <div v-else>
          <!-- 역할이 남아있는 경우 (로딩바 돌아감)-->


          <div v-if='player <= bookDetail.book.roleCnt'>
            <div class='profile-background q-pa-sm'>
              <div class='dashed column items-center' style='justify-content: center;'>
                <h6 class='q-mr-md q-mt-md q-mb-none player-name'><br>도토리 유저 찾는 중</h6>
                <div class='main'>
                  <!--                <img src="../../assets/DotoriImages/acorn_character_img.png" class="profile-pic q-mr-md q-mt-none q-mb-md"-->
                  <!--                   alt="user-profile-img">-->
                  <div class='loading_circle'></div>
                </div>
                <div class='row q-mt-none q-mb-sm' style='visibility: hidden'>
                  <q-btn unelevated rounded color='my-brown q-mr-sm btn-font'>
                    <q-menu fit anchor='bottom start' self='top left'>
                      <q-item clickable>
                        <q-item-section>토끼</q-item-section>
                      </q-item>
                      <q-item clickable>
                        <q-item-section>거북이</q-item-section>
                      </q-item>
                    </q-menu>
                    <div>역할 선택하기</div>
                  </q-btn>
                  <q-btn unelevated rounded color='my-brown q-ml-sm btn-font'>
                    <div>커스텀 아바타</div>
                  </q-btn>
                </div>
              </div>
            </div>
          </div>
          <div v-else>
            <!--사용자 없음-->
            <div class='profile-background q-pa-sm'>
              <div class='dashed column items-center relative-position '>
                <div class='q-ma-md'></div>
                <div style='margin: 1px'></div>
                <img src='../../assets/DotoriImages/acorn_character_img.png'
                     class='q-my-lg' style='height: 1.5em;width: 1.5em'
                >
                <div style='margin: 1px'></div>
                <!--                <div class = "q-mt-xs"></div>-->
                <div class='q-ma-md'></div>
              </div>
            </div>

          </div>


        </div>
      </div>
    </div>
  </div>
</template>
<script setup>
  import {storeToRefs} from 'pinia';
  import {useOpenViduStore} from 'stores/openvidu';
  import {ref, watch} from 'vue';
  import {useQuasar} from 'quasar';

  const $q = useQuasar();
  const openViduStore = useOpenViduStore();
  const {playerList, bookDetail, memberId} = storeToRefs(openViduStore);
  const {session} = openViduStore;


  const makeSendingRoleData = () => {
    sendingRoleData.value.roleList = bookDetail.value.roles;
    sendingRoleData.value.playerList = playerList.value;
  };

  watch(playerList.value, (newItems, oldItems) => {
    newItems.forEach((newItem, index) => {
      if (oldItems[index] !== newItem && index !== 0) {
        playerList.value[index] = {...newItem};
      }
    });
  }, {deep: true});

  const toggleRole = (player, selectedIndex) => {
    // 역할 선택
    if (playerList.value[player - 1].roleIndex === selectedIndex) {
      $q.notify({
        color: 'white',
        textColor: 'green-9',
        message: '이미 선택했어요!',
        position: 'center',
        timeout: 500,
        icon: 'mdi-alert-circle-outline',
      });
      return;
    }
    // 역할 중복 선택 불가
    const selectedRole = bookDetail.value.roles[selectedIndex];
    if (selectedRole && selectedRole.selected) {
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: selectedRole.name + '역할은 다른 친구가 선택했어요!',
        position: 'center',
        timeout: 500,
        icon: 'mdi-alert-outline',
      });
      return;
    }
    const prevSelectedRole = bookDetail.value.roles[playerList.value[player - 1].roleIndex];
    if (prevSelectedRole) {
      prevSelectedRole.selected = false;
    }
    if (selectedRole) {
      selectedRole.selected = true;
      playerList.value[player - 1].roleName = selectedRole.name;
      playerList.value[player - 1].roleIndex = selectedIndex;
    }

    makeSendingRoleData();
    sendRoleInfoToOpenVidu();
  };

  const cancelRole = (player) => {
    bookDetail.value.roles[playerList.value[player - 1].roleIndex].selected = false;
    playerList.value[player - 1].roleName = '역할 선택하기';
    playerList.value[player - 1].roleIndex = 5;
    makeSendingRoleData();
    sendRoleInfoToOpenVidu();
  };


  const sendingRoleData = ref({
    playerList: null,
    roleList: null,
  });

  const sendRoleInfoToOpenVidu = () => {
    return new Promise((resolve, reject) => {
      session.signal({
        data: JSON.stringify(sendingRoleData.value),
        to: [],
        type: 'signal:update-role',
      })
        .then(() => {
          resolve('역할 선택 정보 전송 성공');
        })
        .catch(error => {
          reject(error);
        });
    });
  };

  // 방 참여자의 역할 정보가 변경되었다는 이벤트를 수신하면 방 참여자들은 변경 내용을 반영한다.
  session.on('signal:update-role', (event) => {
    const receivedData = JSON.parse(event.data);
    playerList.value = receivedData.playerList;
    bookDetail.value.roles = receivedData.roleList;
  });


</script>


<style scoped>
  .bg-my-brown {
    background: #C7A96E !important;
  }

  .bg-my-brown {
    background: #be6a4a !important;
  }

  .player {
    background: rgba(218, 201, 157, 0.87);
    border-radius: 20px 20px 20px 20px;
  }

  .profile-pic {
    background: white;
    border-radius: 50%;
    height: 1.5em;
    width: 1.5em;

  }

  .profile-background {
    background: white;
    border-radius: 15px;
    margin: 1px;
  }

  .no-user-background {
    background: white;
    border-radius: 20px;
    margin: 1px;
  }

  .dashed {
  //border: solid rgba(110, 78, 31, 0.62) 2px;
    border-radius: 13px;
    box-shadow: -4px -4px 4px rgba(218, 201, 157, 0.45) inset;
    background: rgba(218, 201, 157, 0.45);
    width: 100%;
    padding: 5px;

  }

  .dashed-white {
    border: dashed rgba(110, 78, 31, 0) 5px;
    border-radius: 20px 20px 20px 20px;
    width: 100%;
  }

  .round {
    border-radius: 20px 20px 20px 20px;
  }

  .btn-font {
    color: #a84d2f;
    font-family: NPSfontBold;
  }


  .player-name {
    color: #6E4E1F;
    font-family: NPSfontBold;
  }


  .loading_circle {
    width: 45px;
    height: 44px;
    margin: 10px auto;

    border: 10px solid white;
    border-bottom: 10px solid #6E4E1F;
    border-radius: 50%;

    animation: load 1.5s linear infinite;
  }

  @keyframes load {
    0% {
      transform: rotate(0deg);
    }
    100% {
      transform: rotate(360deg);
    }
  }

</style>
