import axios from "axios";
// import { httpStatusCode } from "./http-status";


function localAxios() {
  const instance = axios.create({
    baseURL: 'http://localhost:8080',
    withCredentials: true,
    headers: {
      "Content-Type": "application/json;charset=utf-8",
    },
  });
  // instance.defaults.headers.post["withCredentials"] = true;
  // instance.defaults.headers.get["withCredentials"] = true;
  // instance.defaults.headers.delete["withCredentials"] = true;
  instance.defaults.headers.post["Content-Type"] = "application/json";
  instance.defaults.headers.get["Content-Type"] = "application/json";
  instance.defaults.headers.delete["Content-Type"] = "application/json";
  // instance.defaults.headers.put["Content-Type"] = "application/json";

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
              'http://localhost:8080/api/members/reaccesstoken',
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
export { localAxios };
