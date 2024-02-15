<template>

  <!--    onMount시점에 내 비디오를 켜고, 캔버스를 생성해서 모델을 입힌다. DONE-->
  <!--    비디오와 캔버스를 displaynone하고-->
  <!--    publish가 된다-->
  <!--  <q-btn color="brown-5" class="col-2 npsfont" label="방만들기" @click="connectToNewSession"></q-btn>-->
  <!--  <div class="col-2"></div>-->
  <!--  <q-input color="brown-5" class="col-2 npsfont" v-model='sessionId'></q-input>-->
  <!--  <q-btn color="brown-5" class="col-2 npsfont" label="방참가" @click="connectToAnotherSession"></q-btn>-->
  <video ref="videoPlayer" id="videoPlayer" autoplay style="display: none"></video>
</template>

<script setup>


  import {onMounted, ref} from 'vue';
  import * as THREE from 'three';
  import {OrbitControls} from 'three/addons/controls/OrbitControls';
  import {GLTFLoader} from 'three/addons/loaders/GLTFLoader';
  import {FaceLandmarker, FilesetResolver} from '@mediapipe/tasks-vision';
  import {useOpenViduStore2} from 'stores/openvidu2';
  import {useOpenViduStore} from 'stores/openvidu';

  const ovstore = useOpenViduStore();
  const ovstore2 = useOpenViduStore2();
  const videoPlayer = ref(null);
  const sessionId = ref('');
  const props = defineProps({currentRoles: Set, myAvatar: String});
  const emit = defineEmits(['changeCanvasStream']);
  const connectToNewSession = () => {
    ovstore2.connectToNewSession();
  };
  const connectToAnotherSession = () => {
    ovstore2.connectToAnotherSession(sessionId.value);
  };
  onMounted(() => {
  console.log("publishMyVideoOnMount실행중~~====================================================")
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
    console.log("찾아보려는 탈 주소 : " + ovstore.bookDetail.roles[ovstore.myRole-ovstore.minRole].maskPath);
    const avatar = new Avatar(ovstore.bookDetail.roles[ovstore.myRole-ovstore.minRole].maskPath, scene.scene);

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
      const canvasStream = myCanvas.captureStream();
      emit('changeCanvasStream', canvasStream);
      ovstore.changeCanvasStream(canvasStream);
      console.log("캔버스 스트림 보냈음!!!!!!!!!!!!!!!!!");

      //첫페이지에서만 실행될 코드....
      //첫페이지에 내 역할이 있다면 실행한다....
      if (props.currentRoles.has(ovstore.myRole)) {
        const publisher = ovstore.OV.initPublisher(undefined, {
          audioSource: canvasStream.getAudioTracks()[0], // The source of audio. If undefined default microphone
          videoSource: canvasStream.getVideoTracks()[0], // The source of video. If undefined default webcam
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
      }

    }

    runDemo();
  });
</script>


<style scoped>

</style>
