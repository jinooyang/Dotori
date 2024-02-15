<template>
  <Header />
  <!--  <Header></Header>-->
  <!--  <div style="background: #d2fff7" class = "q-pa-lg row">-->
  <div class="q-pa-lg row">
    <div
      class="q-ma-lg q-pa-lg col-8 offset-2">
      <div class="row flex justify-center ">
        <!--        <div class="col-2"></div>-->
        <div class='flex justify-center q-ma-none q-pa-md'>
          <div v-if='ovstore.mainStreamManager'>
            <ov-video class='border-brown' :stream-manager='ovstore.mainStreamManager'
                      :id='ovstore.mainStreamManager.stream.streamId' />
          </div>
          <div v-for='(sub,index) in ovstore.subscribers' :key='sub.stream.connection.connectionId'>
            <ov-video :stream-manager='sub'
                      :id='sub.stream.streamId'
                      class='border-brown' />
          </div>
        </div>
        <!--        <div class="col-2"></div>-->
      </div>

      <div class="row flex justify-center">
        <h2 class="npsfont q-mb-md">수고하셨습니다</h2>


      </div>
      <div class="row flex justify-center">
        <h4 class="npsfont q-mb-md q-mt-none">결과는 마이페이지에서 확인하세요!</h4>
      </div>
      <div class="row flex justify-center">
        <q-btn unelevated rounded color="my-brown" class="q-mx-sm" size="1.5em" label="홈으로" @click='moveToMainPage' />
        <q-btn unelevated rounded color="my-brown" class="q-mx-sm" size="1.5em" label="마이페이지" @click='moveToMyPage' />
      </div>
    </div>
  </div>
</template>
<script setup>
  import Header from 'components/CommonComponents/Header.vue';
  import OvVideo from 'components/RecordingPageComponents/OvVideo.vue';
  import {useOpenViduStore} from 'stores/openvidu';
  import {onMounted} from 'vue';
  import {useRouter} from 'vue-router';
  import {localAxios} from 'src/axios/http-commons';
  import {useQuasar} from 'quasar';

  const axios = localAxios();
  const $q = useQuasar();

  const router = useRouter();
  const ovstore = useOpenViduStore();

  const moveToMainPage = () => {
    ovstore.session.disconnect();
    removeMemberFromRoom();
    router.push('/');
  };
  const moveToMyPage = () => {
    ovstore.session.disconnect();
    removeMemberFromRoom();
    router.push('/my-page/info');
  };

  const removeMemberFromRoom = () => {
    return axios.delete(`/api/rooms/remove/${ovstore.roomId}/${ovstore.memberId}`);
  };

  onMounted(() => {
    const publisher = ovstore.OV.initPublisher(undefined, {
      // audioSource: myRealCanvas.value.captureStream().getAudioTracks()[0], // The source of audio. If undefined default microphone
      // videoSource: myRealCanvas.value.captureStream().getVideoTracks()[0], // The source of video. If undefined default webcam
      // videoSource: canvasStream, // The source of video. If undefined default webcam
      // videoSource: undefined, // The source of video. If undefined default webcam
      publishAudio: true, // Whether you want to start publishing with your audio unmuted or not
      publishVideo: true, // Whether you want to start publishing with your video enabled or not
      resolution: '640x480', // The resolution of your video
      frameRate: 30, // The frame rate of your video
      insertMode: 'APPEND', // How the video is inserted in the target element 'video-container'
      // mirror: false, // Whether to mirror your local video or not
    });
    ovstore.publish(publisher);

  });
  const unpublish = () => {
    if (ovstore.isPublished) ovstore.unpublish();
  };
</script>

<style scoped>
  .end-border {
    border: dashed 5px #C7A96E;
    background: white;
    border-radius: 20px
  }

  img {
    background: white;
    border-radius: 20px;
  }

  .background-green {
    background: #C7A96E;
    border-radius: 20px;

  }

  @font-face {
    font-family: 'NPSfontBold';
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2310@1.0/NPSfontBold.woff2') format('woff2');
    font-weight: 700;
    font-style: normal;
  }

  .npsfont {
    font-family: 'NPSfontBold';
  }

  .bg-my-brown {
    background: #C7A96E !important;
  }

  .border-brown {
    border: 5px solid rgba(218, 201, 157, 0.87);
    border-radius: 20px;

  }


</style>
