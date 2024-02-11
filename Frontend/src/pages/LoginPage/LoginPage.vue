<template>
  <Header/>
    <div class="bg-brown-3">
        <div
            class="q-pa-md row items-start q-gutter-md flex items-center justify-center"
        >
            <q-card class="my-card bg-white text-black rounded-borders">
                <q-card-section class="top-margin">
                    <div>
                        <div
                            id="text-container"
                            class="text-h6 flex items-center justify-center"
                        >
                            지금 도토리를 시작해 보세요
                        </div>
                        <div
                            id="text-container"
                            class="text-h4 flex items-center justify-center"
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
        const url = 'http://localhost:8080/oauth2/authorization/kakao';
        redirectToAuthUrl(url);
    };

    const naverlogin = () => {
        const url = 'http://localhost:8080/oauth2/authorization/naver';
        redirectToAuthUrl(url);
    };

    const googlelogin = () => {
        const url = 'http://localhost:8080/oauth2/authorization/google';
        redirectToAuthUrl(url);
    };
</script>

<style scoped>
    .bg-brown-3 {
        height: 100vh; /* 뷰포트 높이에 맞게 전체 화면으로 설정 */
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }

    .my-card {
        position: relative; /* 카드의 위치를 상대적으로 설정 */
        z-index: 2;
        height: 400px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        margin: 30px;
    }
    .rounded-borders {
        border-radius: 20px; /* 모서리를 조절할 값 */
    }
    #text-container {
        white-space: pre-line; /* 줄 바꿈을 강제로 지정합니다. */
    }
    /* PNG 이미지를 배경 맨 아래에 추가하는 가상 요소 설정 */
    .bg-brown-3::after {
        content: '';
        background-image: url('../../assets/LoginPageImages/loginbackground.png'); /* 배경 이미지 경로 설정 */
        background-size: cover; /* 배경 이미지를 컨테이너에 맞게 조절 */
        background-position: center bottom; /* 배경 이미지를 가운데 정렬하고 아래에 위치하도록 설정 */
        position: absolute; /* 절대적인 위치 설정 */
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 1; /* 이전 요소들보다 뒤에 위치하도록 설정 */
    }
    .top-margin {
        margin-top: 50px; /* 위쪽 마진 크기 조절 */
    }
    .select_btn-group {
        margin-bottom: 30px; /* 아래쪽 마진 크기 조절 */
    }
</style>
