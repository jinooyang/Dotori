import {onMounted, ref} from 'vue';
import {defineStore} from 'pinia';
import {OpenVidu} from 'openvidu-browser';

import {localAxios} from '../axios/http-commons';
import {useRouter} from 'vue-router';


const router = useRouter();
const axios = localAxios();
export const useOpenViduStore
  = defineStore('openViduStore', () => {


  const OV = new OpenVidu();
  const session = OV.initSession();
  const ovToken = ref(null);

  const apiRootPath = '/api/rooms';

  const roomId = ref(0);
  const memberId = ref(20);
  const memberInfo = ref({
    memberId: 0,
    nickName: '닉네임 조회 실패',
    email: '이메일 조회 실패',
    profileImg: null,
  });
  const isLoggedIn = ref(false);
  const subscribers = ref([]);
  const mainStreamManager = ref();
  var mainStreamManagerReal = null;
  const isPublished = ref(false);
  // 방장인지 아닌지 판단
  const isHost = ref(false);
  const onAir = ref(0);
  //나중에 역할 선택에 따라 변경할 부분
  const minRole = ref();
  const canvasStream = ref();

  const changeCanvasStream = (stream) => {
    canvasStream.value = stream;
  };
  // 방 세션 설정 정보
  const session_properties = ref({});
  // 커넥션 설정 정보
  const connection_properties = ref({});

  // 방 설정 정보
  const roomInfo = ref({
    hostId: 30,
    title: null,
    password: null,
    isRecording: false,
    joinCnt: 0,
    limitCnt: 0,
    isPublic: true,
  });

  // 책, 역할 설정 정보
  const bookDetail = ref({
    book: {},
    roles: [],
    scenes: [],
  });

  const roomInitializationParam = ref({
    sessionProperties: null,
    connectionProperties: null,
    roomInfo: null,
    bookInfo: null,
  });

  const createRoom = (bookmodal) => {
    return new Promise((resolve, reject) => {
      const apiPath = apiRootPath + '/session';
      roomInitializationParam.value.bookInfo = bookmodal;
      roomInitializationParam.value.roomInfo = roomInfo.value;

      axios.post(apiPath, roomInitializationParam.value,{withCredentials: true})
        .then((response) => {
          roomId.value = response.data.roomId;
          ovToken.value = response.data.token;
          resolve(response.data);
        })
        .catch((error) => {
          console.error('방 생성 실패 : ' + error.response);
          reject(error);
        });
    });
  };

  const getConnectionToken = (room) => {  //방에 입장할 때 사용되는 코드
    return new Promise((resolve, reject) => {
      roomInitializationParam.value.bookInfo = room.book;
      roomInitializationParam.value.roomInfo = room;
      roomInfo.hostId = room.hostId;//방 정보에 호스트 아이디가 존재한다. 저장한다
      isHost.value = false;//입장한 사람은 호스트가 아니니까 false
      const apiPath = apiRootPath + `/connection/${room.roomId}`;

      axios.post(apiPath, connection_properties.value,{withCredentials: true})
        .then((response) => {
          roomId.value = response.data.roomId;
          ovToken.value = response.data.token;
          resolve(response.data);
        })
        .catch((error) => {
          console.error(error.response);
          reject(error);
        });
    });
  };

  const addRoomMember = (book) => {
    return new Promise((resolve, reject) => {
      const apiPath = apiRootPath + `/add/${roomId.value}/${memberId.value}/${book.bookId}`;

      axios.post(apiPath,{withCredentials: true})
        .then((response) => {
          bookDetail.value = response.data.bookInfo;
          minRole.value = bookDetail.value.roles[0].roleId;
          resolve(response.data);
        })
        .catch((error) => {
          console.error('방 참여 정보 갱신 처리 중 오류 발생 : ', error.response);
          reject(error);
        });
    });
  };

  const removeRoomMember = () => {
    return new Promise((resolve, reject) => {
      const apiPath = apiRootPath + `/remove/${roomId.value}/${memberId.value}`;

      axios.delete(apiPath,{withCredentials: true})
        .then((response) => {
          resolve(response.data);
        })
        .catch((error) => {
          console.error('방 나가기 정보 갱신 처리 중 오류 발생 : ', error.response);
          reject(error);
        });
    });
  };

  const updateRoom = (isRecording) => {
    return new Promise((resolve, reject) => {
      const apiPath = apiRootPath + `/update/${roomId.value}`;

      roomInfo.value.isRecording = isRecording;

      axios.patch(apiPath, roomInfo.value, {withCredentials: true})
        .then((response) => {
          roomId.value = response.data.roomId;
          resolve(response.data);
        })
        .catch((error) => {
          console.error('방 정보 업데이트 처리 중 문제 발생 : ', error.response);
          reject(error);
        });
    });
  };


  const connectToOpenVidu = () => {
    return new Promise((resolve, reject) => {
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

      session.connect(ovToken.value)
        .then(() => {
          console.log(ovToken.value);
          resolve();
        })
        .catch((error) => {
          console.error('ov와 연결 실패 : ', error);
          reject(error);
        });
    });
  };
  const publish = (publisher) => {
    session.publish(publisher).then(() => {
      mainStreamManager.value = publisher;
      mainStreamManagerReal = publisher;
      console.log('published my video!');
      isPublished.value = true;
    }).catch((error) => {
      // isPublished.value = true;
      console.log(error);
    });
  };

  const unpublish = () => {
    console.log(mainStreamManager.value.streamId);
    session.unpublish(mainStreamManagerReal).then(() => {
      console.log('unpublished my video!!');
      isPublished.value = false;
      mainStreamManager.value = null;
      mainStreamManagerReal = null;
    }).catch((error) => {
      // isPublished.value = false;
      console.log(session.connection);
      console.log(mainStreamManager.value.stream.connection);
      console.log('unpblish failed!' + error);
    });

  };

  const playerList = ref([]);
  const myRole = ref();
  // import {localAxios} from 'src/axios/http-commons';
  // const axios = localAxios();
  const checkAuthStatus = () => {
    console.log('isLoggedIn? : ' + isLoggedIn);
    axios.get('/api/members/status', {withCredentials: true}).then(
      (response) => {
        //로그인 된 상태를 확인하고 저장한다
        isLoggedIn.value = response.data.isAuthenticated;
        if (isLoggedIn.value !== false) {
          console.log("로그인 되어있음!");
          axios.get('/api/members/detail', {withCredentials: true})
            .then((response) => {
              //회원정보를 저장한다
              console.log('회원 정보 조회 성공!');
              console.log(response)
              memberInfo.value = response.data;
              console.log(memberInfo.value);
              memberId.value = response.data.memberId;
              sessionStorage.setItem('memberId', response.data.memberId);
            }).catch((error) => {
            console.log('회원정보 조회 실패' + error);
          });
        }
      },
    ).catch((error) => {
      isLoggedIn.value = false;
      console.log('로그인 확인 실패 : ' + error);
    });
  };

  onMounted(() => {
    checkAuthStatus();
  });
  return {
    roomInfo,
    roomId,
    memberId,
    isHost,
    session,
    playerList,
    ovToken,
    bookDetail,
    roomInitializationParam,
    createRoom,
    connectToOpenVidu,
    addRoomMember,
    updateRoom,
    publish,
    subscribers, mainStreamManager, OV,
    getConnectionToken,
    removeRoomMember,
    onAir,
    unpublish,
    isPublished,
    myRole, minRole, canvasStream, changeCanvasStream, isLoggedIn, memberInfo,
  };
}, {persist: {storage: sessionStorage}});
