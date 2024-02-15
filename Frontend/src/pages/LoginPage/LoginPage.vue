<template>
  <div class="back">
    <Header/>
    <div
      class="q-pa-md row items-start q-gutter-md flex items-center justify-center">
      <q-card class="my-card text-black rounded-borders">
        <q-card-section class="top-margin">
          <div>
            <div
              id="text-container"
              class="text-h6 flex items-center justify-center npsfont"
            >
              지금 도토리를 시작해 보세요
            </div>
            <div
              id="text-container"
              class="text-h5 flex items-center justify-center npsfont"
            >
              간편하게 SNS ID로 시작하기
            </div>
          </div>
        </q-card-section>

        <q-card-actions class="flex items-center justify-center">
          <div class="select_btn-group">
            <q-btn flat @click="kakaologin()">
              <img
                src="../../assets/LoginPageImages/login_btn_kakao.svg"
              />
            </q-btn>
            <q-btn flat @click="naverlogin()">
              <img
                src="../../assets/LoginPageImages/login_btn_naver.svg"
              />
            </q-btn>
            <q-btn flat @click="googlelogin()">
              <img
                src="../../assets/LoginPageImages/login_btn_google.svg"
              />
            </q-btn>
          </div>
        </q-card-actions>
      </q-card>
    </div>
  </div>
</template>

<script setup>
  import Header from 'components/CommonComponents/Header.vue';

  const redirectToAuthUrl = url => {
    window.location.href = url;
  };

  const kakaologin = () => {
    const url = process.env.API_URL+'/oauth2/authorization/kakao';
    redirectToAuthUrl(url);
  };

  const naverlogin = () => {
        const url = process.env.API_URL+'/oauth2/authorization/naver';
    redirectToAuthUrl(url);
  };

  const googlelogin = () => {
    const url = process.env.API_URL+'/oauth2/authorization/google';
    redirectToAuthUrl(url);
  };
</script>

<style scoped>
  .back {
    background-image: url('../../assets/LoginPageImages/doto.PNG'); /* 배경 이미지 경로 설정 */
    background-size: cover; /* 배경 이미지를 화면에 맞게 조절 */
    background-position: center; /* 배경 이미지를 가운데로 정렬 */
    height: 750px;
  }
  .my-card {
    position: absolute; /* 카드의 위치를 상대적으로 설정 */
    z-index: 2;
    height: 300px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    bottom: 250px;
    width : 400px;
    background-color: rgba(255, 255, 255, 0.65);
  }
  .rounded-borders {
    border-radius: 20px; /* 모서리를 조절할 값 */
  }
  #text-container {
    white-space: pre-line; /* 줄 바꿈을 강제로 지정합니다. */
  }
  .top-margin {
    margin-top: 35px; /* 위쪽 마진 크기 조절 */
  }
  .select_btn-group {
    margin-bottom: 50px; /* 아래쪽 마진 크기 조절 */
  }
</style>
