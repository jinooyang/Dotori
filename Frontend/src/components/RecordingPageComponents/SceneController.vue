<script setup>
  import {useOpenViduStore} from 'stores/openvidu';
  import {QSpinnerHourglass, useQuasar} from 'quasar';
  import {localAxios, openviduAxios} from 'src/axios/http-commons';
  import axios from 'axios';
  import router from 'src/router';
  import {useRecordingStore} from 'stores/recording';
  import {computed} from 'vue';

  const recStore = useRecordingStore();

  const local = localAxios();
  const $q = useQuasar();
  const ovstore = useOpenViduStore();
  const props = defineProps(
    {
      curPage: Number,
      customLayoutFolder: String,
    },
  );
  const emit = defineEmits(['moveToPage']);
  let openViduRecordingId;
  const sessionId = ovstore.session.sessionId;

  const openviduRequest = openviduAxios();

  const nextPage = () => {
    if (ovstore.bookDetail.scenes.length > props.curPage) {
      //방장일 경우만 실행하도록 로직을 추가해야함
      if (ovstore.isHost)
        ovstore.session.signal({
            data: props.curPage + 1,
            type: 'page',
          },
        );
      else alert('방장만 페이지를 이동할 수 있습니다');
      // emit('moveToPage', props.curPage + 1);
    } else {
      console.log('마지막 페이지 입니다!');
    }
  };

  const beforePage = () => {
    if (1 < props.curPage) {
      //방장일 경우만 실행하도록 로직을 추가해야함
      if (ovstore.isHost)
        ovstore.session.signal({
            data: props.curPage - 1,
            type: 'page',
          },
        );
      else alert('방장만 페이지를 이동할 수 있습니다');
      // emit('moveToPage', props.curPage - 1);
    } else {
      console.log('첫번째 페이지 입니다!');
    }
  };

  const startOpenViduRecording = () => {

    //모래시계 작동
    ovstore.session.signal({type: 'recordingStartLoading'});

    openviduRequest.post('/openvidu/api/recordings/start',
      {
        'session': sessionId,
        'name': 'TestRecording',
        'hasAudio': true,
        'hasVideo': true,
        'outputMode': 'COMPOSED',
        'recordingLayout': 'CUSTOM',
        'customLayout': props.customLayoutFolder + '/scene-' + props.curPage,
        'resolution': '1280x640',
        'frameRate': 30,
        'shmSize': 536870912,
        'ignoreFailedStreams': false,
      })
      .then((response) => {

        console.log('id : ' + response.data.id);
        console.log('name : ' + response.data.name);
        console.log('hasAudio : ' + response.data.hasAudio);
        console.log('hasAudio : ' + response.data.hasVideo);
        console.log('outputMode : ' + response.data.outputMode);
        console.log('recordingLayout : ' + response.data.recordingLayout);
        console.log('customLayout : ' + response.data.customLayout);
        console.log('frameRate : ' + response.data.frameRate);
        openViduRecordingId = response.data.id;

        //화면 빨간색으로 바꾸는 부분
        //모래시계 작동도 멈춘다
        ovstore.session.signal({
          data: 1,
          type: 'onAir',
        });

      })
      .catch((error) => {
        console.log(error);
        ovstore.session.signal({
          type: 'recordingStartError',
        });
      });
  };

  const stopOpenViduRecording = () => {
    //빨간 테두리 종료
    ovstore.session.signal({
      data: 0,
      type: 'onAir',
    });

    openviduRequest.post(`/openvidu/api/recordings/stop/${openViduRecordingId}`)
      .then((response) => {

        console.log('id : ' + response.data.id);
        console.log('hasAudio : ' + response.data.hasAudio);
        console.log('hasAudio : ' + response.data.hasVideo);
        console.log('outputMode : ' + response.data.outputMode);
        console.log('recordingLayout : ' + response.data.recordingLayout);
        console.log('frameRate : ' + response.data.frameRate);
        console.log('url : ' + response.data.url);

        let clipUrl = response.data.url;
        let toRemove = process.env.OPENVIDU_URL+':8443/openvidu/recordings/';

        let resultUrl = clipUrl.replace(toRemove, '');

        local.post('/api/videos/scenes', {
          roomId: ovstore.roomId,
          sceneOrder: props.curPage,
          savedPath: resultUrl,
        }).then(() => {

          ovstore.session.signal({
            data: clipUrl,
            type: 'recordingSuccess',
          });

        }).catch((error) => {
          ovstore.session.signal({
            type: 'recordingSavedFailed',
          });
        });
      })
      .catch((error) => {
        console.log(error);
        // $q.loading.hide();
        ovstore.session.signal({
          type: 'recordingSavedFailed',
        });
      });
  };

  const mergeVideo = () => {

    if (recStore.checkAllRecComplete() && ovstore.isHost) {
      // if (ovstore.isPublished) ovstore.unpublish();
      //모든 페이지가 녹화 되었을 경우 && 방장일 경우
      //녹화영상 머지 생성 요청을 보낸다
      local.post('/api/videos/scenes/merge', {
        roomId: ovstore.roomId,
      });
      //수고하셨습니다 페이지로 넘어간다
      ovstore.session.signal({
          type: 'end',
        },
      );
    } else {
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: '녹화 되지 않은 페이지가 있습니다. 녹화를 모두 완료 한 후 눌러주세요',
        position: 'center',
        timeout: 500,
      });
      // alert('녹화 되지 않은 페이지가 있습니다. 녹화를 모두 완료 한 후 눌러주세요');
    }
  };


  const viewMyVideo = () => {
    window.open(recStore.videoLink[props.curPage - 1], '_blank');
  };


  const isRecorded = computed(()=>{
    return recStore.isCurPageRecorded(props.curPage)
  })
</script>

<template>
  <div class='controller-container col-4 q-pt-sm'>
    <div class='out-back ' style='height: 100%'>
      <div class='in-back q-pa-sm' style='width: 100%;height: 100%'>

          <div class="row q-my-md flex justify-center items-center">
            <div class='col-4 flex justify-center items-center'>
              <q-btn round color='grey-9' icon='mdi-arrow-left-bold' size='lg' @click='beforePage'
                     :disabled='!ovstore.isHost' />
            </div>
            <div class='col-4 flex justify-center items-center'>
              <q-btn round color='blue-12' icon='mdi-play' size='lg' v-if='!ovstore.onAir'
                     @click='startOpenViduRecording' :disabled='!ovstore.isPublished' />
              <q-btn outline round color='white' text-color='red-5' icon='mdi-stop' size='lg'
                     v-if='ovstore.onAir'
                     @click='stopOpenViduRecording' :disabled='!ovstore.isPublished' />
            </div>
            <div class='col-4  flex justify-center'>
              <q-btn round color='grey-9' icon='mdi-arrow-right-bold' size='lg' @click='nextPage'
                     :disabled='!ovstore.isHost' />
            </div>
          </div>
          <div class="row flex justify-evenly">
            <q-btn class="col-5 npsfont" color='grey-9' label="다시보기" @click='viewMyVideo'
                   :disable="isRecorded===false"
            />
            <q-btn class="col-5 npsfont" color='grey-9' label="완료하기" @click='mergeVideo'
                   :disable='!ovstore.isHost' />
          </div>

      </div>
    </div>
  </div>
</template>

<style scoped>

  .controller-container {
    height: 180px;

  }

  .left-button-container {
    display: flex;
    align-items: center;
    justify-content: center;
  }


  .right-button-container {
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .out-back {
      border: 6px solid rgba(218, 201, 157, 0.87);
      border-radius: 20px;
      padding : 6px;
  }

  .in-back {
    //background: #ffffff;
      background: rgba(223, 208, 170, 0.3);
      border-radius: 15px;

      //border: 1px solid red;

  }

  .button-container {

    height: 100%;
  }

</style>
