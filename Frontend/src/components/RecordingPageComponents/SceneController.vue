<script setup>
    import {useOpenViduStore} from 'stores/openvidu';
    import {QSpinnerHourglass, useQuasar} from 'quasar';
    import {localAxios} from 'src/axios/http-commons';
    import axios from 'axios';
    import router from 'src/router';
    import {useRecordingStore} from 'stores/recording';

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

    const openviduAxios = axios.create({
        baseURL: 'https://dotori.online',
        headers: {
            'Authorization': 'Basic T1BFTlZJRFVBUFA6MTBTU0FGWUE1MDI=',
            'Content-Type': 'application/json',
        },
    });

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
        // $q.loading.show({
        //     message: '녹화 준비 중입니다. 잠시만 기다려주세요!',
        //     spinner: QSpinnerHourglass,
        //     boxClass: 'bg-grey-2 text-grey-9',
        //     spinnerColor: 'brown',
        // });
        //모래시계 작동
        ovstore.session.signal({type:'recordingStartLoading'});


        openviduAxios.post('/openvidu/api/recordings/start',
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
               // $q.loading.hide();
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
                // $q.loading.hide();
                // $q.notify({
                //     color: 'white',
                //     textColor: 'red-9',
                //     message: '문제가 생겼어요! 다시 녹화 시작을 해볼까요?',
                //     position: 'center',
                //     timeout: 500,
                // });
            });
    };

    const stopOpenViduRecording = () => {
      //빨간 테두리 종료
        ovstore.session.signal({
            data: 0,
            type: 'onAir',
        });

        openviduAxios.post(`/openvidu/api/recordings/stop/${openViduRecordingId}`)
            .then((response) => {

                // $q.notify({
                //     color: 'white',
                //     textColor: 'green-9',
                //     message: '녹화가 성공적으로 되었어요! 다음 장면도 녹화하러 가볼까요?',
                //     position: 'center',
                //     timeout: 500,
                // });
                console.log('id : ' + response.data.id);
                console.log('hasAudio : ' + response.data.hasAudio);
                console.log('hasAudio : ' + response.data.hasVideo);
                console.log('outputMode : ' + response.data.outputMode);
                console.log('recordingLayout : ' + response.data.recordingLayout);
                console.log('frameRate : ' + response.data.frameRate);
                console.log('url : ' + response.data.url);

                let clipUrl = response.data.url;
                let toRemove = 'https://dotori.online:8443/openvidu/recordings/';

                let resultUrl = clipUrl.replace(toRemove, '');

                local.post('/api/videos/scenes', {
                    roomId: ovstore.roomId,
                    sceneOrder: props.curPage,
                    savedPath: resultUrl,
                }).then(() => {
                    recStore.recComplete(props.curPage);//현재 페이지 녹화 완료된 정보를 저장
                  ovstore.session.signal({
                    type: 'recordingSavedSuccess',
                  });
                    ovstore.session.signal({
                        data: recStore.recHistory,
                        type: 'recfin',
                    });
                }).catch((error) => {
                  ovstore.session.signal({
                    type: 'recordingSavedFailed',
                  });
                    // $q.notify({
                    //     color: 'white',
                    //     textColor: 'red-9',
                    //     message: '녹화가 되지 않았아요! 아쉽지만 다시 녹화를 해볼까요?',
                    //     position: 'center',
                    //     timeout: 500,
                    // });
                });
            })
            .catch((error) => {
                console.log(error);
                // $q.loading.hide();
              ovstore.session.signal({
                type: 'recordingSavedFailed',
              });
                // $q.notify({
                //     color: 'white',
                //     textColor: 'red-9',
                //     message: '녹화가 되지 않았아요! 아쉽지만 다시 녹화를 해볼까요?',
                //     position: 'center',
                //     timeout: 500,
                // });
            });
    };

    const mergeVideo = () => {

        if (recStore.checkAllRecComplete() && ovstore.isHost) {
            //모든 페이지가 녹화 되었을 경우 && 방장일 경우
            //녹화영상 머지 생성 요청을 보낸다
            local.post('/api/videos/scenes/merge', {
                roomId: ovstore.roomId,
            }).then().catch();
            //수고하셨습니다 페이지로 넘어간다
            ovstore.session.signal({
                    type: 'end',
                },
            );
        } else {
            alert('녹화 되지 않은 페이지가 있습니다. 녹화를 모두 완료 한 후 눌러주세요');
        }
    };
</script>

<template>
    <div class='controller-container col-4 q-pt-sm'>
        <div class='out-back ' style='height: 100%'>
            <div class='in-back q-pa-sm' style='width: 100%; height: 100%'>
                <div class='button-container row '>
                    <div class='left-button-container col-3'>
                        <q-btn round color='grey-9' icon='mdi-arrow-left-bold' size='lg' @click='beforePage' :disabled='!ovstore.isHost'/>
                    </div>
                    <div class='col-6 flex justify-center items-center'>
                        <q-btn round color='blue-12' icon='mdi-play' size='lg' v-if='!ovstore.onAir'
                               @click='startOpenViduRecording'  :disabled='!ovstore.isPublished' />
                        <q-btn outline round color='white' text-color='red-5' icon='mdi-stop' size='lg'
                               v-if='ovstore.onAir'
                               @click='stopOpenViduRecording' :disabled='!ovstore.isPublished'/>
                    </div>
                    <div class='right-button-container col-3'>
                        <q-btn round color='grey-9' icon='mdi-arrow-right-bold' size='lg' @click='nextPage' :disabled='!ovstore.isHost'/>
                    </div>
                    <q-btn round color='grey-9' icon='mdi-stop' size='lg' @click='mergeVideo' :disabled='!ovstore.isHost'/>
                </div>
            </div>
        </div>
    </div>
</template>

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

    .play-button-container {
        margin-right: 10px;
    }

    .stop-button-container {
        margin-left: 10px;
    }

    .out-back {
        background: #C7A96E;
        padding: 6px;

    }

    .in-back {
    //background: #ffee9a; background: #ffffff; //border-radius: 15px;
    }

    .button-container {
        background: white;
    //border-radius: 15px; height: 100%; //border: #cc765a dashed 4px;
    }

</style>
