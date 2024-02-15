import axios from 'axios';

function openviduAxios() {
  return axios.create({
    baseURL: process.env.OPENVIDU_URL,
    headers: {
      'Authorization': 'Basic T1BFTlZJRFVBUFA6MTBTU0FGWUE1MDI=',
      'Content-Type': 'application/json',
    },
  });
}

function localAxios() {
  const instance = axios.create({
    baseURL: process.env.API_URL,
    withCredentials: true,
    headers: {
      "Content-Type": "application/json;charset=utf-8",
    },
  });

  instance.defaults.headers.post["Content-Type"] = "application/json";
  instance.defaults.headers.get["Content-Type"] = "application/json";
  instance.defaults.headers.delete["Content-Type"] = "application/json";

  instance.interceptors.response.use(
    response => response,
    async error => {
      if (error.response.status === 401 && !error.config._retry) {
        const errorMessage = error.response.data.error;
        if (errorMessage === 'Access Token is invalid') {
          error.config._retry = true; // 재시도 플래그 설정
          console.log('토큰갱신진입');
          const newAccessToken = await refreshToken(); // 액세스 토큰 갱신
          console.log('토큰갱신완료');
          error.config.headers['accessToken'] = newAccessToken;
          return instance(error.config); // 요청 재시도
        }
      }
      return Promise.reject(error);
    },
  );

  async function refreshToken() {
    try {
      const response = await instance.get(
        '/api/members/reaccesstoken',
      );
      console.log('response', response);
      const accessTokenPrefix = 'accessToken:';
      const startIndex =
        response.data.indexOf(accessTokenPrefix) +
        accessTokenPrefix.length;
      const newAccessToken = response.data.substring(startIndex);
      return newAccessToken;
    } catch (error) {
      console.error('토큰 갱신 실패', error);
      throw error;
    }
  }


  return instance;
}

function imgAxios() {
  const instance = axios.create({
    baseURL: process.env.API_URL,
    withCredentials: true,
    headers: {
      "Content-Type": "multipart/form-data;charset=utf-8",
    },
  });
  return instance;
}
export { localAxios, imgAxios, openviduAxios };
