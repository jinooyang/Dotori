<template>
  <Header />
  <!--  <h1>{{ myAvatar }}</h1>-->
  <!--  role : {{ ovstore.myRole }}-->
  <div class='row flex justify-center q-px-none'>
    <div class='col-11'>
      <div class='entire-container row'>
        <div class='right-container q-pr-sm q-pt-sm q-pl-sm col-9'>
          <MainScene :curPage='curPage' :currentScene='currentScene' />
          <side-bar :curPage='curPage' @moveToPage='moveToPage' :currentScene='currentScene'></side-bar>
        </div>
        <div class='left-container col-3 q-pt-sm'>
          <Script :currentScene='currentScene' />
          <SceneController :curPage='curPage' :customLayoutFolder="customLayoutFolder" @moveToPage='moveToPage' />
        </div>
      </div>
    </div>
  </div>
  <!--  <PublishMyVideo :currentRoles='currentRoles' :myAvatar='myAvatar' @changeCanvasStream="changeCanvasStream" />-->
  <video ref="videoPlayer" id="videoPlayer" autoplay style="display: none"></video>
</template>


<script setup>
  import SideBar from 'components/RecordingPageComponents/SideBar.vue';
  import MainScene from 'components/RecordingPageComponents/MainScene.vue';
  import Script from 'components/RecordingPageComponents/Script.vue';
  import SceneController from 'components/RecordingPageComponents/SceneController.vue';
  import {onMounted, ref} from 'vue';
  import * as THREE from 'three';
  import {OrbitControls} from 'three/addons/controls/OrbitControls';
  import {GLTFLoader} from 'three/addons/loaders/GLTFLoader';
  import {FaceLandmarker, FilesetResolver} from '@mediapipe/tasks-vision';
  import {useOpenViduStore} from 'stores/openvidu';
  import Header from 'components/CommonComponents/Header.vue';
  import {useRouter} from 'vue-router';

  const router = useRouter();
  import {useRecordingStore} from 'stores/recording';
  import {QSpinnerHourglass, useQuasar} from 'quasar';

  const $q = useQuasar();
  const recStore = useRecordingStore();
  const videoPlayer = ref(null);


  const ovstore = useOpenViduStore();

  const curPage = ref(1);

  //현재 페이지의 역할을 넣는다
  //ovstore에 있는 bookDetail에 있는 roles를 onMount 시점에 가져와서 초기화를 시켜준다
  const currentRoles = ref(new Set());
  const currentScene = ref({});

  const myCanvasStream = ref();
  const myRealCanvas = ref();
  const myAvatar = ref('');

  const customLayoutFolder = ref(null);

  //영상 퍼블리시
  const publish = () => {
    if (!ovstore.isPublished) {
      const publisher = ovstore.OV.initPublisher(undefined, {
        audioSource: myRealCanvas.value.captureStream().getAudioTracks()[0], // The source of audio. If undefined default microphone
        videoSource: myRealCanvas.value.captureStream().getVideoTracks()[0], // The source of video. If undefined default webcam
        // videoSource: canvasStream, // The source of video. If undefined default webcam
        // videoSource: undefined, // The source of video. If undefined default webcam
        publishAudio: true, // Whether you want to start publishing with your audio unmuted or not
        publishVideo: true, // Whether you want to start publishing with your video enabled or not
        resolution: '640x480', // The resolution of your video
        frameRate: 30, // The frame rate of your video
        insertMode: 'APPEND', // How the video is inserted in the target element 'video-container'
        // mirror: false, // Whether to mirror your local video or not
      });
      ovstore.publish(
        //add publisher later
        publisher,
      );
    }
  };

  //퍼블리시 끊기
  const unpublish = () => {
    if (ovstore.isPublished) ovstore.unpublish();
  };

  //페이지를 이동한다
  //페이지를 이동할때마다 현재 페이지의 역할 목록을 초기화 시켜준다
  //스크립트 또한 초기화 시켜준다
  const moveToPage = (nextPage) => {
    if (ovstore.onAir && ovstore.isHost) {
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: '녹화중에는 이동할 수 없습니다',
        position: 'center',
        timeout: 500,
        icon: 'mdi-alert-outline',
      });
      return;
    }

    curPage.value = nextPage;
    //역할 목록을 변경해준다
    currentRoles.value = getRoles(curPage.value);

    console.log('현재 페이지 : ' + curPage.value);
    console.log('currentRoles :');
    if (currentRoles.value.has(ovstore.myRole))
      console.log();
    else {
      console.log('내 차례 아니다!');
    }

    //페이지 정보를 변경해준다
    currentScene.value = ovstore.bookDetail.scenes[curPage.value - 1];

    //값을 다 바꿨으면 내 역할과 확인해서 비디오를 켤지 말지를 판단한다
    //내가 연극할 차례일때
    if (currentRoles.value.has(ovstore.myRole)) {
      console.log('MYTURN');
      //퍼블리시중이 아니라면 시작
      if (!ovstore.isPublished) publish();

    }
    //내 차례가 아닐때
    else if (!currentRoles.value.has(ovstore.myRole)) {
      console.log('NOT MY TURN');
      //퍼블리시 중이라면 종료
      if (ovstore.isPublished) unpublish();
    }
  };

  //curPage값에 따라 역할 목록을 반환한다.
  const getRoles = (page) => {
    //scriptDto를 받아온다
    let scriptDto = ovstore.bookDetail.scenes[page - 1].scriptDto;
    console.log('!!!!!!!!!!!!!!!!!!!!!');
    console.log(scriptDto);
    //역할을 만들 set을 생성한다
    const set = new Set();
    for (let script in scriptDto) {
      // console.log('script!!');
      // console.log(script);

      let roleId = scriptDto[script].roleDto.roleId;//역할 번호
      console.log(roleId + '역할은 이 페이지에서 활동합니다');
      set.add(roleId);
    }
    return set;
  };

  //mounted 후 실행되는 코드..초기화 작업
  onMounted(() => {
    console.log('recordingRoomOnMount실행중~~==========================================================================');
    console.log('bookDetail');
    console.log(ovstore.bookDetail);
    //총 페이지 수를 저장한다
    recStore.totalPages = ovstore.bookDetail.scenes.length;
    recStore.videoLink = [];
    for (let i in recStore.totalPages) {
      recStore.videoLink.push('');
    }
    //session 설정 추가
    //페이지이동 버튼이 눌리면 다같이 페이지를 이동한다
    ovstore.session.on('signal:page', (event) => {
      const nextPage = Number(event.data);
      moveToPage(nextPage);
    });
    ovstore.session.on('signal:recordingSuccess', (event) => {
      // const recHistory = Number(event.data);
      $q.notify({
        color: 'white',
        textColor: 'green-9',
        message: '녹화가 성공적으로 되었어요!',
        position: 'center',
        timeout: 500,
      });
      recStore.videoLink[curPage.value - 1] = event.data;
      console.log((curPage.value - 1) + '페이지에 비디오 링크 저장 : ' + event.data.url);
      recStore.recComplete(curPage.value);
    });
    ovstore.session.on('signal:end', (event) => {
      if (ovstore.isPublished) {
        ovstore.unpublish()
      }
      router.push('/end');
    });

    ovstore.session.on('signal:onAir', (event) => {
      //로딩중이면 멈춘다
      if (Number(event.data) === 1) {
        $q.loading.hide();
      }
      //빨간색으로 바꾼다
      ovstore.onAir = Number(event.data);
    });

    //녹화 시작 준비중이면 로딩 시작
    ovstore.session.on('signal:recordingStartLoading', (event) => {
      $q.loading.show({
        message: '녹화 준비 중입니다. 잠시만 기다려주세요!',
        spinner: QSpinnerHourglass,
        boxClass: 'bg-grey-2 text-grey-9',
        spinnerColor: 'brown',
      });
    });

    ovstore.session.on('signal:recordingStartError', (event) => {
      //녹화 시작에 문제가 생겼을 경우
      $q.loading.hide();
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: '문제가 생겼어요! 다시 녹화 시작을 해볼까요?',
        position: 'center',
        timeout: 500,
      });
    });


    ovstore.session.on('signal:recordingSavedFailed', (event) => {
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: '녹화가 되지 않았아요! 아쉽지만 다시 녹화를 해볼까요?',
        position: 'center',
        timeout: 500,
      });
    });
    //척페이지 역할 초기화
    currentRoles.value = getRoles(1);
    //첫 페이지 정보 넣기
    currentScene.value = ovstore.bookDetail.scenes[0];

    //내 아바타 주소 받아옴!
    myAvatar.value = ovstore.bookDetail.roles[ovstore.myRole - ovstore.minRole].maskPath;

    //녹화용 Custom Layout 경로 지정
    let splited = ovstore.bookDetail.book.bookImg.split('/');
    let folderName = splited[splited.length - 1]; // 파일 이름과 확장자 가져오기 ex('rabbit-and-turtle.png')
    customLayoutFolder.value = folderName.split('.')[0]; // 확장자 제거 ex('rabbit-and-turtle')
    console.log('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$:LAYOUT' + customLayoutFolder.value);


    // 여기서부터 모델링 코드
    // =======================================================================================================================

    console.log('publishMyVideoOnMount실행중~~====================================================');

    /**
     * Returns the world-space dimensions of the viewport at `depth` units away from
     * the camera.
     */
    function getViewportSizeAtDepth(camera, depth) {
      const viewportHeightAtDepth = 2 * depth * Math.tan(THREE.MathUtils.degToRad(0.5 * camera.fov));
      const viewportWidthAtDepth = viewportHeightAtDepth * camera.aspect;
      return new THREE.Vector2(viewportWidthAtDepth, viewportHeightAtDepth);
    }

    /**
     * Creates a `THREE.Mesh` which fully covers the `camera` viewport, is `depth`
     * units away from the camera and uses `material`.
     */
    function createCameraPlaneMesh(camera, depth, material) {
      if (camera.near > depth || depth > camera.far) {
        console.warn('Camera plane geometry will be clipped by the `camera`!');
      }
      const viewportSize = getViewportSizeAtDepth(camera, depth);
      const cameraPlaneGeometry = new THREE.PlaneGeometry(viewportSize.width, viewportSize.height);
      cameraPlaneGeometry.translate(0, 0, -depth);
      return new THREE.Mesh(cameraPlaneGeometry, material);
    }

    class BasicScene {
      constructor() {
        this.lastTime = 0;
        this.callbacks = [];
        // Initialize the canvas with the same aspect ratio as the video input
        this.height = window.innerHeight / 2;
        this.width = (this.height * 1280) / 720;

        // Set up the Three.js scene, camera, and renderer
        this.scene = new THREE.Scene();
        this.camera = new THREE.PerspectiveCamera(60, this.width / this.height, 0.01, 5000);
        this.renderer = new THREE.WebGLRenderer({antialias: true});
        this.renderer.setSize(this.width, this.height);
        THREE.ColorManagement.legacy = false;
        this.renderer.outputEncoding = THREE.sRGBEncoding;
        document.getElementById('canvasDiv').appendChild(this.renderer.domElement);
        // document.body.appendChild(this.renderer.domElement);//???????????????????이거 없어도 될까???
        //이게 있어야 스트림을 뽑아낸다
        // Set up the basic lighting for the scene
        const ambientLight = new THREE.AmbientLight(0xffffff, 0.5);
        this.scene.add(ambientLight);
        const directionalLight = new THREE.DirectionalLight(0xffffff, 0.5);
        directionalLight.position.set(0, 1, 0);
        this.scene.add(directionalLight);
        // Set up the camera position and controls
        this.camera.position.z = 0;
        this.controls = new OrbitControls(this.camera, this.renderer.domElement);
        let orbitTarget = this.camera.position.clone();
        orbitTarget.z -= 5;
        this.controls.target = orbitTarget;
        this.controls.update();
        // Add a video background
        const inputFrameTexture = new THREE.VideoTexture(videoPlayer.value);
        if (!inputFrameTexture) {
          throw new Error('Failed to get the \'input_frame\' texture!');
        }
        inputFrameTexture.encoding = THREE.sRGBEncoding;
        const inputFramesDepth = 500;
        const inputFramesPlane = createCameraPlaneMesh(this.camera, inputFramesDepth, new THREE.MeshBasicMaterial({map: inputFrameTexture}));
        this.scene.add(inputFramesPlane);
        // Render the scene
        this.render();
        // window.addEventListener('resize', this.resize.bind(this));
      }

      resize() {
        this.width = window.innerWidth;
        this.height = window.innerHeight;
        this.camera.aspect = this.width / this.height;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(this.width, this.height);
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        this.renderer.render(this.scene, this.camera);
      }

      render(time = this.lastTime) {
        const delta = (time - this.lastTime) / 1000;
        this.lastTime = time;
        // Call all registered callbacks with deltaTime parameter
        for (const callback of this.callbacks) {
          callback(delta);
        }
        // Render the scene
        this.renderer.render(this.scene, this.camera);
        // Request next frame
        requestAnimationFrame((t) => this.render(t));
      }
    }

    class Avatar {
      constructor(url, scene) {
        this.loader = new GLTFLoader();
        this.morphTargetMeshes = [];
        this.url = url;
        this.scene = scene;
        this.loadModel(this.url);
      }

      loadModel(url) {
        this.url = url;
        this.loader.load(
          // URL of the model you want to load
          url,
          // Callback when the resource is loaded
          (gltf) => {
            if (this.gltf) {
              // Reset GLTF and morphTargetMeshes if a previous model was loaded.
              this.gltf.scene.remove();
              this.morphTargetMeshes = [];
            }
            this.gltf = gltf;
            // console.log();
            this.scene.add(gltf.scene);
            this.init(gltf);
          },
          // Called while loading is progressing
          (progress) => console.log('Loading model...', 100.0 * (progress.loaded / progress.total), '%'),
          // Called when loading has errors
          (error) => console.error(error));
      }

      init(gltf) {
        gltf.scene.traverse((object) => {
          // Register first bone found as the root
          if (object.isBone && !this.root) {
            this.root = object;
            console.log(object);
          }
          // Return early if no mesh is found.
          if (!object.isMesh) {
            // console.warn(`No mesh found`);
            return;
          }
          const mesh = object;
          // Reduce clipping when model is close to camera.
          mesh.frustumCulled = false;
          // Return early if mesh doesn't include morphable targets
          if (!mesh.morphTargetDictionary || !mesh.morphTargetInfluences) {
            // console.warn(`Mesh ${mesh.name} does not have morphable targets`);
            return;
          }
          this.morphTargetMeshes.push(mesh);
        });
      }

      updateBlendshapes(blendshapes) {
        for (const mesh of this.morphTargetMeshes) {
          if (!mesh.morphTargetDictionary || !mesh.morphTargetInfluences) {
            // console.warn(`Mesh ${mesh.name} does not have morphable targets`);
            continue;
          }
          for (const [name, value] of blendshapes) {
            if (!Object.keys(mesh.morphTargetDictionary).includes(name)) {
              // console.warn(`Model morphable target ${name} not found`);
              continue;
            }
            const idx = mesh.morphTargetDictionary[name];
            mesh.morphTargetInfluences[idx] = value;
          }
        }
      }

      /**
       * Apply a position, rotation, scale matrix to current GLTF.scene
       * @param matrix
       * @param matrixRetargetOptions
       * @returns
       */
      applyMatrix(matrix, matrixRetargetOptions) {
        const {decompose = false, scale = 1} = matrixRetargetOptions || {};
        if (!this.gltf) {
          return;
        }
        // Three.js will update the object matrix when it render the page
        // according the object position, scale, rotation.
        // To manually set the object matrix, you have to set autoupdate to false.
        matrix.scale(new THREE.Vector3(scale, scale, scale));
        this.gltf.scene.matrixAutoUpdate = false;
        // Set new position and rotation from matrix
        this.gltf.scene.matrix.copy(matrix);
      }

      /**
       * Takes the root object in the avatar and offsets its position for retargetting.
       * @param offset
       * @param rotation
       */
      offsetRoot(offset, rotation) {
        if (this.root) {
          this.root.position.copy(offset);
          if (rotation) {
            let offsetQuat = new THREE.Quaternion().setFromEuler(new THREE.Euler(rotation.x, rotation.y, rotation.z));
            this.root.quaternion.copy(offsetQuat);
          }
        }
      }
    }

    let faceLandmarker;
    const scene = new BasicScene();
    console.log('찾아보려는 탈 주소 : ' + myAvatar.value);
    const avatar = new Avatar(myAvatar.value, scene.scene);

    function detectFaceLandmarks(time) {
      if (!faceLandmarker) {
        return;
      }
      const landmarks = faceLandmarker.detectForVideo(videoPlayer.value, time);
      // Apply transformation
      const transformationMatrices = landmarks.facialTransformationMatrixes;
      if (transformationMatrices && transformationMatrices.length > 0) {
        let matrix = new THREE.Matrix4().fromArray(transformationMatrices[0].data);
        // Example of applying matrix directly to the avatar
        avatar.applyMatrix(matrix, {scale: 40});
      }
      // Apply Blendshapes
      // console.log('Apply Blendshapes');
      const blendshapes = landmarks.faceBlendshapes;
      if (blendshapes && blendshapes.length > 0) {
        const coefsMap = retarget(blendshapes);
        avatar.updateBlendshapes(coefsMap);
      }
    }

    function retarget(blendshapes) {
      const categories = blendshapes[0].categories;
      let coefsMap = new Map();
      for (let i = 0; i < categories.length; ++i) {
        const blendshape = categories[i];
        // Adjust certain blendshape values to be less prominent.
        switch (blendshape.categoryName) {
          case 'browOuterUpLeft':
            blendshape.score *= 1.2;
            break;
          case 'browOuterUpRight':
            blendshape.score *= 1.2;
            break;
          case 'eyeBlinkLeft':
            blendshape.score *= 1.2;
            break;
          case 'eyeBlinkRight':
            blendshape.score *= 1.2;
            break;
          default:
        }
        coefsMap.set(categories[i].categoryName, categories[i].score);
      }
      return coefsMap;
    }

    function onVideoFrame(time) {
      // Do something with the frame.
      detectFaceLandmarks(time);
      // Re-register the callback to be notified about the next frame.
      videoPlayer.value.requestVideoFrameCallback(onVideoFrame);
    }

    // Stream webcam into landmarker loop (and also make video visible)
    async function streamWebcamThroughFaceLandmarker() {

      function onAcquiredUserMedia(stream) {
        videoPlayer.value.srcObject = stream;
        videoPlayer.value.onloadedmetadata = () => {
          videoPlayer.value.play();
        };
      }

      try {
        const evt = await navigator.mediaDevices.getUserMedia({
          audio: false,
          video: {
            facingMode: 'user',
            width: 1280,
            height: 720,
          },
        });
        onAcquiredUserMedia(evt);
        videoPlayer.value.requestVideoFrameCallback(onVideoFrame);
      } catch (e) {
        console.error(`Failed to acquire camera feed: ${e}`);
      }
    }

    async function runDemo() {
      const myCanvas = document.querySelector('canvas');
      myCanvas.setAttribute('id', 'myCanvas');
      myRealCanvas.value = myCanvas;
      myCanvas.style.display = 'none';
      await streamWebcamThroughFaceLandmarker();
      const vision = await FilesetResolver.forVisionTasks('https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.1.0-alpha-16/wasm');
      faceLandmarker = await FaceLandmarker.createFromModelPath(vision, 'https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/latest/face_landmarker.task');
      await faceLandmarker.setOptions({
        baseOptions: {
          delegate: 'GPU',
        },

        runningMode: 'VIDEO',
        outputFaceBlendshapes: true,
        outputFacialTransformationMatrixes: true,
      });
      console.log('Finished Loading MediaPipe Model.');
      // myCanvas.style.border = '10px solid red';
      myCanvasStream.value = myCanvas.captureStream();
      // myRealCanvasStream = myCanvas.captureStream();
      // emit('changeCanvasStream', canvasStream);
      // ovstore.changeCanvasStream(canvasStream);
      // console.log("캔버스 스트림 보냈음!!!!!!!!!!!!!!!!!");

      //첫페이지에서만 실행될 코드....
      //첫페이지에 내 역할이 있다면 실행한다....
      // if (props.currentRoles.has(ovstore.myRole)) {
      //   const publisher = ovstore.OV.initPublisher(undefined, {
      //     audioSource: canvasStream.getAudioTracks()[0], // The source of audio. If undefined default microphone
      //     videoSource: canvasStream.getVideoTracks()[0], // The source of video. If undefined default webcam
      //     // videoSource: canvasStream, // The source of video. If undefined default webcam
      //     // videoSource: undefined, // The source of video. If undefined default webcam
      //     publishAudio: true, // Whether you want to start publishing with your audio unmuted or not
      //     publishVideo: true, // Whether you want to start publishing with your video enabled or not
      //     resolution: '640x480', // The resolution of your video
      //     frameRate: 30, // The frame rate of your video
      //     insertMode: 'APPEND', // How the video is inserted in the target element 'video-container'
      //     // mirror: false, // Whether to mirror your local video or not
      //   });
      //
      //   ovstore.publish(publisher);
      // }

      if (currentRoles.value.has(ovstore.myRole)) {
        publish();
      }
    }

    runDemo();

  });

</script>
<style scoped>
  @font-face {
    font-family: 'NPSfontBold';
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2310@1.0/NPSfontBold.woff2') format('woff2');
    font-weight: 700;
    font-style: normal;
  }


  .entire-container {
    height: 85vh;
    //border: green solid 1px; //background: #d2fff7;
  }

  .left-container {
    height: 100%;
    //border: red solid 1px;
  }

  .right-container {
    height: 100%;
    //border: blue solid 1px;
  }


</style>
