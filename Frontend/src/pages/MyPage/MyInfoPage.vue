<template>
  <headermypage />
  <q-page
    style="
            position: absolute;
            top: 67%;
            left: 53%;
            transform: translate(-45%, -48%);
        "
  >
    <div class="row flex justify-center">
<!--            <div class="text-h3 npsfont" style="color : #C7A96E">내 정보</div>-->
    </div>
    <hr class="q-my-md" style="border: white 1px solid" />
    <div class="row ">
      <div style="width: 310px;height: 310px;border-radius: 50%;border: #DFD0AA 5px solid;"
           class="q-mb-lg flex justify-center items-center relative-position">
        <img :src="memberInfo.profileImg" style="width: 300px;height: 300px;border-radius: 50%;object-fit: cover; " />
        <q-btn
          unelevated
          rounded

          class="absolute-bottom-right my-info-btn"
          @click="openFilePopup" style = "transform: translate(-20px,-10px)"
        ><h6 class = "q-ma-none">편집</h6></q-btn>
        <div class = "absolute-top-left npsfont q-pa-xs "
             style="
             background: white;
             border :5px solid white;
              transform: rotate(-48.8deg) translate(-20px,24px);
               border-radius: 100px;
               color : #DFD0AA;">
          <h5 class = "q-ma-none">사진</h5>
        </div>
      </div>
<div class="q-mx-lg"></div>
      <div class="relative-position row flex justify-center items-center" style="
                        width: 310px;
                        height: 310px;
                        border-radius: 50%;
                        object-fit: cover;
                        border : 5px solid #DFD0AA;
                    ">
        <div class = "absolute-top-left npsfont q-pa-xs "
             style="
             background: white;
             border :5px solid white;
              transform: rotate(-48.8deg) translate(-20px,24px);
               border-radius: 100px;
               color : #DFD0AA;">
          <h5 class = "q-ma-none">이름</h5>
        </div>

        <!--        닉네임 변경 인풋-->
        <q-input dense label="새로운 닉네임을 입력하세요" v-model="nickName" color="brand"
                 v-if="!isChange" />
        <div class = "flex absolute-bottom-right" style="transform: translate(0px,-10px)">
        <q-btn v-if="!isChange" @click="changeNickname(nickName)" unelevated rounded
               class="my-info-save-btn btn-bg-save">저장
        </q-btn>
        <q-btn v-if="!isChange" @click="isChange = !isChange" unelevated rounded
               class="my-info-btn btn-bg-cancel">취소
        </q-btn>
        </div>
        <!--닉네임 보여주기 div-->
        <div v-if="isChange"><h4 class="q-ma-none npsfont" style="color: #C7A96E">
          {{ openViduStore.memberInfo.nickName }}</h4>
        </div>
        <q-btn v-if="isChange" @click="isChange= !isChange;nickName = openViduStore.memberInfo.nickName" unelevated rounded
               class="my-info-btn absolute-bottom-right" style = "transform: translate(-20px,-10px)"><h6 class = "q-ma-none">편집</h6>
        </q-btn>
      </div>


    </div>
  </q-page>
</template>

<script setup>
  import {useRouter} from 'vue-router';
  import {localAxios, imgAxios} from 'src/axios/http-commons';
  import {useOpenViduStore} from 'stores/openvidu';
  import {storeToRefs} from 'pinia';
  import {useQuasar} from 'quasar';
  import Headermypage from 'components/CommonComponents/Headermypage.vue';
  import {ref, watch} from 'vue';

  const $q = useQuasar();
  const openViduStore = useOpenViduStore();
  const {memberInfo} = storeToRefs(openViduStore);
  const axios = localAxios();
  const fileAxios = imgAxios();
  const router = useRouter();
  const nickName = ref('');
  const isChange = ref(true);
  // watch(openViduStore.memberInfo, (newItems, oldItems) => {
  //   nickName.value = newItems.nickName;
  // }, {deep: true});
  const changeProfileImg = async (event) => {
    const formData = new FormData();
    console.log(event.target.files[0]);
    const newProfileImg = event.target.files[0];
    formData.append('profileImage', newProfileImg);
    try {
      const response = await fileAxios.put('/api/members/profile-image', formData);
      memberInfo.value.profileImg = response.data.profileImage;
      $q.notify({
        color: 'white',
        textColor: 'green-9',
        message: '프로필 이미지가 변경되었어요!',
        position: 'center',
        timeout: 500,
        icon: 'mdi-account-box-multiple-outline',
      });
      router.push('/my-page/info');
    } catch (error) {
      $q.loading.hide();
      $q.notify({
        color: 'white',
        textColor: 'red-9',
        message: '문제가 생겼어요! 다시 프로필 이미지를 변경해볼까요?',
        position: 'center',
        timeout: 500,
        icon: 'mdi-alert-outline',
      });
    }
  };

  const openFilePopup = async () => {
    // 파일 선택 창 열기
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = 'image/*'; // 이미지 파일만 선택 가능하도록 설정할 수 있음
    fileInput.onchange = changeProfileImg;
    fileInput.click();
  };
  const changeNickname = (newNickname) => {
    axios
      .put('/api/members/update_nickname', {}, { params: { newNickname } })
      .then((response) => {
        $q.notify({
          color: 'white',
          textColor: 'green-9',
          message: '닉네임이 변경되었어요!',
          position: 'center',
          timeout: 500,
          icon: 'mdi-account-box-multiple-outline',
        });
        openViduStore.memberInfo.nickName = newNickname;
        isChange.value = !isChange.value;
      })
      .catch((error) => {
        $q.loading.hide();
        $q.notify({
          color: 'white',
          textColor: 'red-9',
          message: '문제가 생겼어요! 다시 닉네임을 바꿔볼까요?',
          position: 'center',
          timeout: 500,
          icon: 'mdi-alert-outline',
        });
      });
  };
  // const changeNickname = async (newNickname) => {
  //   try {
  //     const response = await axios.put(
  //       '/api/members/update_nickname',
  //       {},
  //       {
  //         params: {newNickname},
  //       },
  //     );
  //     $q.notify({
  //       color: 'white',
  //       textColor: 'green-9',
  //       message: '닉네임이 변경되었어요!',
  //       position: 'center',
  //       timeout: 500,
  //       icon: 'mdi-account-box-multiple-outline',
  //     });
  //     router.push('/my-page/info');
  //   } catch (error) {
  //     $q.loading.hide();
  //     $q.notify({
  //       color: 'white',
  //       textColor: 'red-9',
  //       message: '문제가 생겼어요! 다시 닉네임을 바꿔볼까요?',
  //       position: 'center',
  //       timeout: 500,
  //       icon: 'mdi-alert-outline',
  //     });
  //   }
  // };


</script>

<style lang="scss" scoped>
  .my-info-btn {
    background-color: #DFD0AA;
    font-family: 'NPSfontBold';
    color: white;
  }
  .my-info-save-btn {
    background-color: #C7A96E;
    font-family: 'NPSfontBold';
    color: white;
  }
.btn-bg-save{
  background: #C7A96E;
  border-radius: 100px 0px 0px 100px;
}
  .btn-bg-cancel{
    background: #DFD0AA;
    border-radius: 0px 100px 100px 0px;
  }
  .profile-bg-white {
    background-color: white;
    border-radius: 50%;
    height: 200px;
    width: 200px;
    border: 5px solid #DFD0AA;
  }

  .light-brown-bg {
    background-color: $dotori-deep-brown;
  }

  .input-box {
    background: white;
    border-radius: $dotori-border-radius;
    width: 100%;
  }


</style>
