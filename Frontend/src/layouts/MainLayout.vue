<template>
    <Header />
    <div class="q-md">
        <q-carousel
            arrows
            infinite
            :autoplay="autoplay"
            navigation
            animated
            v-model="slide"
            height="600px"
        >
            <q-carousel-slide
                name="first"
                img-src="https://cdn.quasar.dev/img/mountains.jpg"
            >
                <div class="absolute-bottom custom-caption">
                    <div class="text-h2">First stop</div>
                    <div class="text-subtitle1">Mountains</div>
                </div>
                <div class="absolute-bottom custom-button">
                    <q-btn
                        color="primary"
                        label="시작하기"
                        router-link
                        to="/login"
                    />
                </div>
            </q-carousel-slide>
            <q-carousel-slide
                name="second"
                img-src="../assets/mainpage/main2.png"
            >
                <div class="absolute-bottom custom-caption">
                    <div class="text-h2">Second stop</div>
                    <div class="text-subtitle1">Famous City</div>
                </div>
                <div class="absolute-bottom custom-button">
                    <q-btn
                        color="primary"
                        label="시작하기"
                        router-link
                        to="/login"
                    />
                </div>
            </q-carousel-slide>
            <q-carousel-slide
                name="third"
                img-src="https://cdn.quasar.dev/img/parallax2.jpg"
            >
                <div class="absolute-bottom custom-caption">
                    <div class="text-h2">Third stop</div>
                    <div class="text-subtitle1">Famous Bridge</div>
                </div>
                <div class="absolute-bottom custom-button">
                    <q-btn
                        color="primary"
                        label="시작하기"
                        router-link
                        to="/login"
                    />
                </div>
            </q-carousel-slide>
        </q-carousel>
    </div>
    <div class="q-md">
        <q-parallax :height="900" :speed="0.3">
            <template v-slot:media>
                <img src="../assets/login/loginbackground.png" />
            </template>

            <div
                ref="animatedText"
                class="absolute-top text-left text-black text-h3 text2"
            >
                왜 도토리에요?
            </div>
        </q-parallax>
    </div>
    <div class="col-6">
        <q-img src="https://cdn.quasar.dev/img/parallax2.jpg">
            <div
                ref="animatedText2"
                class="absolute-top text-h3 text-left text3"
            >
                다양한 탈
            </div>
        </q-img>
    </div>
    <div>
        <q-btn color="primary" label="시작하기" router-link to="/login" />
    </div>
</template>

<script setup>
    import Header from 'layouts/Header.vue';
    import {ref, onMounted, watchEffect} from 'vue';

    const slide = ref('first');
    //메인페이지 캐러셀 자동반복
    const autoplay = ref(true);
    //화면안에 요소가 들어오면 아래에서 올라오기
    const animatedTextRef = ref(null);
    const animatedTextRef2 = ref(null);

    onMounted(() => {
        // animatedTextRef.value에 직접 DOM 요소를 할당
        animatedTextRef.value = document.querySelector('.text2');
        animatedTextRef2.value = document.querySelector('.text3');
    });

    const observeElement = element => {
        if (element instanceof Element) {
            const observer = new IntersectionObserver(entries => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        element.classList.add('entered');
                    } else {
                        element.classList.remove('entered');
                    }
                });
            });

            observer.observe(element);
        }
    };
    watchEffect(() => {
        observeElement(animatedTextRef.value);
        observeElement(animatedTextRef2.value);
    });
</script>

<style lang="scss" scoped>
    .custom-caption {
        text-align: center;
        padding: 12px;
        color: white;
    }

    .custom-button {
        text-align: center;
        padding: 70px;
    }

    .custom-caption {
        text-align: center;
        padding: 400px;
        color: black;
    }

    .custom-button {
        text-align: center;
        padding: 70px;
    }
    // 글씨 나타나기
    .text2 {
        padding: 200px;
        opacity: 0;
        transform: translateY(20px);
        transition: opacity 1s ease-in-out, transform 1s ease-in-out;
    }

    .text2.entered {
        opacity: 1;
        transform: translateY(0);
    }
    // .text3 {
    // padding: 20px;
    // opacity: 0;
    // transform: translateY(20px);
    // transition: opacity 1s ease-in-out, transform 1s ease-in-out;
    // }

    // .text3.entered {
    // opacity: 1;
    // transform: translateY(0);
    // }
    .q-img__content > div {
        background: none !important; /* 배경을 없애는 스타일 */
    }
</style>
