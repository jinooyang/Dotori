import {onMounted, ref} from 'vue';
import {defineStore} from 'pinia';
import {OpenVidu} from 'openvidu-browser';

import {localAxios} from '../axios/http-commons';
import {useRouter} from 'vue-router';


const axios = localAxios();
export const useWebGL
  = defineStore('webGLStore', () => {



  return {


  };
}, {persist: {storage: sessionStorage}});
