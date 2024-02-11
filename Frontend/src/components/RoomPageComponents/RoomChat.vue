<template>
  <div style='height: 100%' class='background-green q-pa-sm'>
    <div style='height: 100%' class='background-yellow q-pa-sm'>
      <div class='column'>
        <div class='background-white'>
          <!-- 채팅 로그 -->
          <div ref='chatLog' id='chatLog' style='height: 90px; overflow-y: auto;'>
            <div v-for='(message, index) in messageList' :key='index' class='q-mx-sm'>{{ message }}</div>
          </div>
        </div>

        <div class='row '>
          <q-input color='brown-1' bg-color='brown-1' v-model='chatMessage' @keyup.enter='sendMessage'
                   placeholder='메시지를 입력하세요' class='col-11' />
          <q-btn color='my-brown' bg-color='white' @click='sendMessage' class='col-1 q-pa-none npsfont chat'>전송</q-btn>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
  import {ref, onMounted, defineProps} from 'vue';
  import {useOpenViduStore} from 'stores/openvidu';
  const openViduStore = useOpenViduStore();
  let playerNickname = null;
  const {session, memberInfo} = openViduStore;
  const chatMessage = ref('');
  const messageList = ref([]);

  onMounted(() => {
    playerNickname = memberInfo.nickName;
    entermessage(playerNickname);
  });

  session.on('signal:chat', (event) => {
    const data = JSON.parse(event.data);
    appendMessage(data.nickname, data.message);
    scrollToBottom();
  });

  session.on('signal:alert', (event) => {
    const message = event.data;
    messageList.value.push(message);
    scrollToBottom();
  });

  const sendMessage = () => {
    if (chatMessage.value && session) {

      const data = {
        message: chatMessage.value,
        nickname: playerNickname,
      };
      session.signal({
        data: JSON.stringify(data),
        type: 'chat',
      });
      chatMessage.value = '';
    }
  };

  const entermessage = (player) => {
    const formattedmessage = `*** ${player}님이 입장하셨습니다 ***`;
    session.signal({
      data: formattedmessage,
      type: 'alert',
    });
  }

  // const outmessage = (player) => {
  //   const formattedmessage = `*** ${player}님이 떠나셨습니다 ***`;
  //   session.signal({
  //     data: formattedmessage,
  //     type: 'alert',
  //   });
  // }

  const appendMessage = (nickname, message) => {
    const formattedMessage = `${nickname}: ${message}`;
    messageList.value.push(formattedMessage);
    // scrollToBottom(); // 메시지 추가 후 자동 스크롤
  };



  const scrollToBottom = () => {
    let chatLog = document.getElementById('chatLog');
    chatLog.scrollTop = chatLog.scrollHeight;
  };
</script>

<style scoped>
  .bg-my-brown {
    background: #C7A96E !important;
  }

  .input-background {
    background-color: floralwhite;
    height: 1em;

  }

  .send-button {
    height: 1em;
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
    background: white;
    height: 7.5em;
    //color : #a84d2f; border-radius: 10px 10px 10px 10px; font-family: NPSfontBold; //border: solid #cc765a 2px;

  }

  .chat {
    border-radius: 20px 20px 20px 20px;
    //border: solid #cc765a 2px;
  }

  .npsfont {
    font-family: 'NPSfontBold';
  }
</style>
