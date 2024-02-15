import {onMounted, ref} from 'vue';
import {defineStore} from 'pinia';
import {OpenVidu} from 'openvidu-browser';

import {localAxios} from '../axios/http-commons';
import {useRouter} from 'vue-router';
import axios from 'axios';


export const useOpenViduStore2
  = defineStore('openViduStore2', () => {

  const OV = new OpenVidu();
  const session = OV.initSession();


  const sessionId = ref('');
  const ovToken = ref('');
  const subscribers = ref([]);
  const publisher = ref();
  //axios 준비한다
  const instance = axios.create({
    baseURL: 'https://dotori.online',
    headers: {
      'Authorization': 'Basic T1BFTlZJRFVBUFA6MTBTU0FGWUE1MDI=',
      'Content-Type': 'application/json',
    },
  });
  //session 설정을 해준다
  //새로운 스트림이 생기면 그 스트림에 구독한다
  session.on('streamCreated', ({stream}) => {
    const subscriber = session.subscribe(stream, stream.streamId);
    subscribers.value.push(subscriber);
  });
  //스트림이 사라지면 그 스트림은 구독을 취소한다
  session.on('streamDestroyed', ({stream}) => {
    const index = subscribers.value.indexOf(stream.streamManager, 0);
    if (index >= 0) {
      subscribers.value.splice(index, 1);
    }
  });

  //session id를 바꿔주는 함수
  const changeSessionId = (id) => {
    sessionId.value = id;
  };

  //새로운 session을 만들어서 거기에 연결한다
  const connectToNewSession = () => {
    instance.post('/openvidu/api/sessions')
      .then((response) => {
        //새로 생성된 sessionId를 저장한다
        sessionId.value = response.data.id;
        console.log('session id : ' + sessionId.value);

        //sessionId에 연결하여 토큰을 받아온다
        instance.post('/openvidu/api/sessions/' + sessionId.value + '/connection')
          .then((response) => {
            ovToken.value = response.data.token;
            console.log('토큰 : ' + ovToken.value);

            //token 정보를 가지고 방에 연결한다
            session.connect(ovToken.value)
              .then(() => {
                console.log('방에 참여 완료');
              }).catch((error) => {
              console.log(error);
            });


          })
          .catch((error) => {
            console.log(error);
          });
      })
      .catch((error) => {
        console.log(error);
      });

  };

  //다른 사람이 만들어둔 session에 연결한다
  const connectToAnotherSession = (id) => {
    //sessionId에 연결하여 토큰을 받아온다
    instance.post('/openvidu/api/sessions/' + id + '/connection')
      .then((response) => {
        ovToken.value = response.data.token;
        console.log('토큰 : ' + ovToken.value);
        //token 정보를 가지고 방에 연결한다
        session.connect(ovToken.value)
          .then(() => {
            console.log('방에 참여 완료');
          }).catch((error) => {
          console.log(error);
        });
      })
      .catch((error) => {
        console.log(error);
      });
  };


  return { changeSessionId, connectToNewSession, connectToAnotherSession};
}, {persist: {storage: sessionStorage}});
