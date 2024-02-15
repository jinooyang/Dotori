<template>
  <Headermain />
  <MainPageVideo/>
  <!-- <MainPageCarousel/> -->
<!--  <div v-if="ovstore.isLoggedIn">로그인되어있음!</div>-->
<!--  <div class="row">-->
<!--    <div class="col-12">-->

<!--      <div class="row" style="height: 250px"></div>-->
<!--      <div ref="animatedTextRef1" class="animated-text">-->
<!--        <ElementOne />-->
<!--      </div>-->
<!--      <div class="row" style="height: 250px;"></div>-->
<!--      <div ref="animatedTextRef2" class="animated-text">-->
<!--        <ElementTwo />-->
<!--      </div>-->
<!--&lt;!&ndash;      <div class="row" style="height: 250px"></div>&ndash;&gt;-->
<!--&lt;!&ndash;      <div ref="animatedTextRef3" class="animated-text">&ndash;&gt;-->
<!--&lt;!&ndash;        <ElementThree />&ndash;&gt;-->
<!--&lt;!&ndash;      </div>&ndash;&gt;-->
<!--      <div class="row" style="height: 250px"></div>-->
<!--      <div ref="animatedTextRef4" class="animated-text">-->
<!--        <ElementFour />-->
<!--      </div>-->
<!--      <div class="row" style="height: 300px"></div>-->

<!--    </div>-->
<!--  </div>-->
</template>

<script setup>
  import {ref, onMounted, watchEffect} from 'vue';
  import MainPageCarousel from 'components/MainPageComponents/MainPageCarousel.vue';
  import ElementOne from 'components/MainPageComponents/ElementOne.vue';
  import ElementTwo from 'components/MainPageComponents/ElementTwo.vue';
  import ElementThree from 'components/MainPageComponents/ElementThree.vue';
  import ElementFour from 'components/MainPageComponents/ElementFour.vue';
  import MainPageVideo from 'src/components/MainPageComponents/MainPageVideo.vue';
  import Headermain from 'components/CommonComponents/Headermainpage.vue';
  import {localAxios} from 'src/axios/http-commons';
  import {useOpenViduStore} from 'stores/openvidu';

  const ovstore = useOpenViduStore();

  const axios = localAxios();
  //화면안에 요소가 들어오면 아래에서 올라오기
  // const animatedTextRef1 = ref(null);
  // const animatedTextRef2 = ref(null);
  // const animatedTextRef3 = ref(null);
  // const animatedTextRef4 = ref(null);

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
    // observeElement(animatedTextRef1.value);
    // observeElement(animatedTextRef2.value);
    // observeElement(animatedTextRef3.value);
    // observeElement(animatedTextRef4.value);
  });

  // const fetchMemberInfo = async () => {
  //   try {
  //     const response = await axiosInstance.get(
  //       'http://localhost:8080/api/members/detail',
  //     );
  //     const memberInfo = response.data;
  //
  //     dummyUser.value.nickName = memberInfo.nickName || '';
  //   } catch (error) {
  //     console.error('Error fetching member info:', error);
  //   }
  // };

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
  .animated-text {
    opacity: 0;
    transform: translateY(20px);
    transition: opacity 1s ease-in-out, transform 1s ease-in-out;
  }

  .animated-text.entered {
    opacity: 1;
    transform: translateY(0);
  }

  .q-img__content > div {
    background: none !important; /* 배경을 없애는 스타일 */
  }
</style>
