<script setup>
  import {ref, onMounted} from 'vue';
  import axios from 'axios';
  import {OpenVidu} from 'openvidu-browser';
  import OvVideo from 'src/webrtctest/OvVideo.vue';
  import VideoCard from 'components/MyPageComponents/VideoCard.vue';

  // import UserVideo from 'src/webrtctest/UserVideo.vue';
  const OV = new OpenVidu();
  const session = OV.initSession();
  const publisher = OV.initPublisher('mytestID2', {insertMode: 'APPEND'});

  const subscribers = ref([]);
  const mainStreamManager = ref();
  const sessionId = ref('default');
  const token = ref('');

  // -------------------------------------------------------------------------------------------------------------

  const instance = axios.create({
    baseURL: 'https://dotori.online',
    headers: {
      'Authorization': 'Basic T1BFTlZJRFVBUFA6MTBTU0FGWUE1MDI=',
      'Content-Type': 'application/json',
    },
  });

  const createSession = () => {
    instance.post('/openvidu/api/sessions')
      .then((response) => {
        console.log(response);
        console.log('세션아이디 : ' + response.data.id);
        sessionId.value = response.data.id;
      })
      .catch((error) => {
        console.log(error);
      });
  };

  const createConnection = () => {
    instance.post('/openvidu/api/sessions/' + sessionId.value + '/connection')
      .then((response) => {
        console.log(response);
        console.log('토큰 : ' + response.data.token);
        token.value = response.data.token;

      })
      .catch((error) => {
        console.log(error);
      });
  };


  const joinRoom = () => {

    //세션 설정을 하자
    // 세션에 스트림이 생기면 subscriber를 추가한다(구독자)
    session.on('streamCreated', ({stream}) => {
      const subscriber = session.subscribe(stream, stream.streamId);
      console.log('subscriber added!!!');
      subscribers.value.push(subscriber);
    });

    // 세션에서 스트림이 삭제되면 subscriber를 삭제한다(구독 취소)
    session.on('streamDestroyed', ({stream}) => {
      const index = subscribers.value.indexOf(stream.streamManager, 0);
      if (index >= 0) {
        subscribers.value.splice(index, 1);
      }
    });

    //세션에 연결한다
    session.connect(token.value).then(() => {
      console.log('연결 성공!!');
      //연결을 성공했으면 publish할 준비를 한다
      let myPublisher = OV.initPublisher(undefined, {
        //audioSource: undefined, // The source of audio. If undefined default microphone
        //videoSource: undefined, // The source of video. If undefined default webcam
        publishAudio: true, // Whether you want to start publishing with your audio unmuted or not
        publishVideo: true, // Whether you want to start publishing with your video enabled or not
        resolution: '640x480', // The resolution of your video
        frameRate: 30, // The frame rate of your video
        insertMode: 'APPEND', // How the video is inserted in the target element 'video-container'
        // mirror: false, // Whether to mirror your local video or not
      });
      // Set the main video in the page to display our webcam and store our Publisher

      //myStreamManager에 내 영상 데이터를 담는다. 밑에서 찍어낸다
      mainStreamManager.value = myPublisher;
      // publisher.value = myPublisher;

      //내 영상을 내보낸다
      session.publish(publisher).then(()=>{
        addAVATAR();
      });


    }).catch((error) => {
      console.log(error);
      console.log('연결 실패!!');
    });
  };


  const updateMainVideoStreamManager = (stream) => {
    if (mainStreamManager.value === stream) return;
    mainStreamManager.value = stream;
  };
</script>
<!-- -&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;&#45;-->
<template>
  <h1>WELCOME TO TEST PAGE</h1>
  sessionId : {{ sessionId }}<br />
  token : {{ token }}<br />
  <div class='row'>
    <h6 class='col-2 flex items-center q-ma-none'>세션 아이디 :</h6>
    <q-input v-model='sessionId' class='col'></q-input>
  </div>
  <q-btn label='create Session' @click='createSession' />
  <q-btn label='create Connection' @click='createConnection' />
  <q-btn label='joinRoom' @click='joinRoom' />

  <video autoplay id="mytestID2"></video>

  <div v-if='mainStreamManager'>
    <ov-video :stream-manager='mainStreamManager' />
  </div>
  <hr />
  <h1>{{ subscribers.length }}</h1>
  <ov-video v-for='sub in subscribers' :key='sub.stream.connection.connectionId' :stream-manager='sub'
            @click.native='updateMainVideoStreamManager(sub)'
            :id='sub.stream.streamId' />


</template>
<script>
  /* Copyright 2023 The MediaPipe Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */


  //임포트한다
  import * as THREE from 'three';
  import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls';
  import { GLTFLoader } from 'three/examples/jsm/loaders/GLTFLoader';
  import { FilesetResolver, FaceLandmarker } from '@mediapipe/tasks-vision';

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
      console.warn("Camera plane geometry will be clipped by the `camera`!");
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
      this.height = window.innerHeight /2;
      this.width = (this.height * 1280) / 720;
      // Set up the Three.js scene, camera, and renderer
      this.scene = new THREE.Scene();
      this.camera = new THREE.PerspectiveCamera(60, this.width / this.height, 0.01, 5000);
      this.renderer = new THREE.WebGLRenderer({ antialias: true });
      this.renderer.setSize(this.width, this.height);
      THREE.ColorManagement.legacy = false;
      this.renderer.outputEncoding = THREE.sRGBEncoding;
      document.body.appendChild(this.renderer.domElement);//???????????????????
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
      const video = document.getElementById("mytestID");
      const inputFrameTexture = new THREE.VideoTexture(video);
      if (!inputFrameTexture) {
        throw new Error("Failed to get the 'input_frame' texture!");
      }
      inputFrameTexture.encoding = THREE.sRGBEncoding;
      const inputFramesDepth = 500;
      const inputFramesPlane = createCameraPlaneMesh(this.camera, inputFramesDepth, new THREE.MeshBasicMaterial({ map: inputFrameTexture }));
      this.scene.add(inputFramesPlane);
      // Render the scene
      this.render();
      window.addEventListener("resize", this.resize.bind(this));
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
          console.log();
          this.scene.add(gltf.scene);
          this.init(gltf);
        },
        // Called while loading is progressing
        (progress) => console.log("Loading model...", 100.0 * (progress.loaded / progress.total), "%"),
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
      const { decompose = false, scale = 1 } = matrixRetargetOptions || {};
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









  const addAVATAR = ()=>{


    let faceLandmarker;
    let video;
    const scene = new BasicScene();
    const avatar = new Avatar("src/assets/raccoon_head.glb", scene.scene);
    function detectFaceLandmarks(time) {
      if (!faceLandmarker) {
        return;
      }
      const landmarks = faceLandmarker.detectForVideo(video, time);
      // Apply transformation
      const transformationMatrices = landmarks.facialTransformationMatrixes;
      if (transformationMatrices && transformationMatrices.length > 0) {
        let matrix = new THREE.Matrix4().fromArray(transformationMatrices[0].data);
        // Example of applying matrix directly to the avatar
        avatar.applyMatrix(matrix, { scale: 40 });
      }
      // Apply Blendshapes
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
          case "browOuterUpLeft":
            blendshape.score *= 1.2;
            break;
          case "browOuterUpRight":
            blendshape.score *= 1.2;
            break;
          case "eyeBlinkLeft":
            blendshape.score *= 1.2;
            break;
          case "eyeBlinkRight":
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
      video.requestVideoFrameCallback(onVideoFrame);
    }
    // Stream webcam into landmarker loop (and also make video visible)
    async function streamWebcamThroughFaceLandmarker() {
      video = document.getElementById("mytestID");
      function onAcquiredUserMedia(stream) {
        video.srcObject = stream;
        video.onloadedmetadata = () => {
          video.play();
        };
      }
      try {
        const evt = await navigator.mediaDevices.getUserMedia({
          audio: false,
          video: {
            facingMode: "user",
            width: 1280,
            height: 720
          }
        });
        onAcquiredUserMedia(evt);
        video.requestVideoFrameCallback(onVideoFrame);
      }
      catch (e) {
        console.error(`Failed to acquire camera feed: ${e}`);
      }
    }
    async function runDemo() {
      await streamWebcamThroughFaceLandmarker();
      const vision = await FilesetResolver.forVisionTasks("https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.1.0-alpha-16/wasm");
      faceLandmarker = await FaceLandmarker.createFromModelPath(vision, "https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/latest/face_landmarker.task");
      await faceLandmarker.setOptions({
        baseOptions: {
          delegate: "GPU"
        },
        runningMode: "VIDEO",
        outputFaceBlendshapes: true,
        outputFacialTransformationMatrixes: true
      });
      console.log("Finished Loading MediaPipe Model.");
    }
    runDemo();
  }


</script>
<style scoped>
canvas{
  width: 300px;
  height: 300px;
}
</style>
