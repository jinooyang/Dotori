<template>
  <Header/>
    <div class="bg-brown-3">
        <div class="q-pa-md">
            <q-btn color="teal" @click="showLoading" label="Show Loading" />
        </div>
    </div>
</template>

<script setup>
    import {useQuasar} from 'quasar';
    import {onBeforeUnmount} from 'vue';
    import Header from 'components/CommonComponents/Header.vue';

    const quasar = useQuasar();
    let timer;

    onBeforeUnmount(() => {
        if (timer !== void 0) {
            clearTimeout(timer);
            if (quasar.loading) {
                quasar.loading.hide();
            }
        }
    });

    const showLoading = () => {
        if (quasar.loading) {
            quasar.loading.show({
                message: '회원가입 중 입니다. 잠시만 기다려주세요.',
            });

            timer = setTimeout(() => {
                if (quasar.loading) {
                    quasar.loading.hide();
                }
                timer = void 0;
            }, 3000);
        }
    };
</script>

<style lang="scss" scoped>
    .bg-brown-3 {
        height: 100vh; /* 뷰포트 높이에 맞게 전체 화면으로 설정 */
        display: flex;
        flex-direction: column;
        justify-content: space-between;
    }
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
    .q-pa-md {
        z-index: 2;
    }
</style>
