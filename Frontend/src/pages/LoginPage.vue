<template>
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
                            <img src="../assets/login/login_btn_kakao.svg" />
                        </q-btn>
                        <q-btn flat @click="naverlogin()">
                            <img src="../assets/login/login_btn_naver.svg" />
                        </q-btn>
                        <q-btn flat @click="googlelogin()">
                            <img src="../assets/login/login_btn_google.svg" />
                        </q-btn>
                    </div>
                </q-card-actions>
            </q-card>
        </div>
    </div>
    <div>
        <q-btn
            color="primary"
            label="테스트용 로그인완료"
            router-link
            to="/signup"
        />
    </div>
</template>

<script setup>
    import {ref, onMounted} from 'vue';
    // import {useCookies} from '@vueuse/integrations/useCookies';

    // const cookies = useCookies();

    const showSocialLoginPopup = url => {
        const popupHeight = '500';
        const popupWidth = '500';
        let popupOptions = `height=${popupHeight},width=${popupWidth},left=${
            (window.screen.width - popupWidth) / 2
        },top=${
            (window.screen.height - popupHeight) / 2
        },scrollbars=yes,resizable=yes`;
        openPopup(url, popupOptions);
    };
    const openPopup = (url, options) => {
        window.open(url, '_blank', options);
    };

    //     const doLogout = () => {
    //   cookies.remove('user-key')
    //   userKey.value = ''
    //   user.value = {}
    // }
    const buildAuthUrl = (
        baseURL,
        clientId,
        redirectUri,
        responseType,
        scope,
        state,
    ) => {
        return `${baseURL}?response_type=${responseType}&client_id=${clientId}&redirect_uri=${redirectUri}&state=${state}&scope=${encodeURIComponent(
            scope,
        )}`;
    };

    const kakaologin = () => {
        const url = buildAuthUrl(
            'https://kauth.kakao.com/oauth/authorize',
            process.env.VUE_APP_KAKAO_JS_KEY,
            process.env.VUE_APP_KAKAO_REDIRECT_URL,
            'code',
            'account_email profile_nickname',
            '',
        );
        showSocialLoginPopup(url);
    };

    const naverlogin = () => {
        const url = buildAuthUrl(
            'https://nid.naver.com/oauth2.0/authorize',
            process.env.VUE_APP_NAVER_CLIENT_ID,
            process.env.VUE_APP_NAVER_REDIRECT_URL,
            'code',
            '',
            '1234',
        );
        showSocialLoginPopup(url);
    };

    const googlelogin = () => {
        const url = buildAuthUrl(
            'https://accounts.google.com/o/oauth2/v2/auth',
            process.env.VUE_APP_GOOGLE_CLIENT_ID,
            process.env.VUE_APP_GOOGLE_REDIRECT_URL,
            'code',
            'email profile',
            '',
        );
        showSocialLoginPopup(url);
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
        background-image: url('../assets/login/loginbackground.png'); /* 배경 이미지 경로 설정 */
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
