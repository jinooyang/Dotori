<template>
    <q-page
        style="
            position: absolute;
            top: 55%;
            left: 50%;
            transform: translate(-50%, -50%);
        "
    >
        <div class="row flex justify-center">
            <div class="text-h3 npsfont">내 정보</div>
        </div>
        <hr class="q-my-md" style="border: white 1px solid" />
        <div class="profile-container column items-center">
            <div
                style="
                    width: 210px;
                    height: 210px;
                    border-radius: 50%;
                    border: #c7a96e 5px solid;
                "
                class="q-mb-lg flex justify-center items-center relative-position"
            >
                <img
                    src="../../assets/MyPageImages/winter.png"
                    style="
                        width: 200px;
                        height: 200px;
                        border-radius: 50%;
                        object-fit: cover;
                    "
                />
                <q-btn
                    unelevated
                    rounded
                    label="편집"
                    class="absolute-bottom-right my-info-btn"
                ></q-btn>
            </div>
            <q-space></q-space>

            <div class="input-box q-py-sm" style="border: 5px solid #c7a96e">
                <div class="profile-info">
                    <div class="q-my-sm row">
                        <q-input
                            dense
                            label="프로필 이름"
                            v-model="dummyUser.nickName"
                            class="col-7 offset-1"
                            color="brand"
                        />
                        <q-btn
                            @click="changeNickname(dummyUser.nickName)"
                            unelevated
                            rounded
                            class="my-info-btn col-2 offset-1"
                            >변경</q-btn
                        >
                    </div>
                    <!--          <div class=" q-my-sm row">-->
                    <!--            <q-input dense label="프로필 이름" :model-value="dummyUser.name" class="col-7 offset-1" />-->
                    <!--            <q-btn unelevated rounded class="my-info-btn col-2 offset-1">변경</q-btn>-->
                    <!--          </div>-->
                    <!--          <div class=" q-my-sm row">-->
                    <!--            <q-input dense label="프로필 이름" :model-value="dummyUser.profileDescription" class="col-7 offset-1" />-->
                    <!--            <q-btn unelevated rounded class="my-info-btn col-2 offset-1">변경</q-btn>-->
                    <!--          </div>-->
                </div>
            </div>
        </div>
    </q-page>
</template>

<script setup>
    import {ref, onMounted} from 'vue';
    import {useRouter} from 'vue-router';
    import {localAxios} from 'src/axios/http-commons';

    const axios = localAxios();
    const router = useRouter();

    const dummyUser = ref({
        profileImg: '111',
        nickName: '',
        profileDescription: '안녕하세요~',
    });

    // API 호출하여 정보 가져오기
    const fetchMemberInfo = async () => {
        try {
            const response = await axios.get(
                '/api/members/detail',
            );
            const memberInfo = response.data;

            dummyUser.value.nickName = memberInfo.nickName || '';
        } catch (error) {
            console.error('Error fetching member info:', error);
        }
    };

    const changeProfileImg = async newProfileImg => {
        try {
            const response = await axiosInstance.put('/update_profileimg', {
                newProfileImg,
            });

            if (response.status === 200) {
                console.log('프로필 이미지 변경 성공');
                router.push('/my-page/info');
            } else {
                console.error('프로필 이미지 변경 실패');
            }
        } catch (error) {
            console.error('API 호출 중 오류 발생:', error);
        }
    };

    const changeNickname = async newNickname => {
        try {
            console.log('함수 내 newNickname:', newNickname);
            const response = await axios.put(
                '/api/members/update_nickname',
                {},
                {
                    params: {newNickname},
                },
            );
            console.log('함수 내 newNickname:', newNickname);
            if (response.status === 200) {
                console.log('닉네임 변경 성공');
                router.push('/my-page/info');
            } else {
                console.error('닉네임 변경 실패');
            }
        } catch (error) {
            console.error('API 호출 중 오류 발생:', error);
        }
    };

    onMounted(() => {
        fetchMemberInfo();
    });
</script>

<style lang="scss" scoped>
    .my-info-btn {
        background-color: #c7a96e;
        font-family: 'NPSfontBold';
        color: white;
    }

    .profile-bg-white {
        background-color: white;
        border-radius: 50%;
        height: 200px;
        width: 200px;
        border: 5px solid #c7a96e;
    }

    .light-brown-bg {
        background-color: $dotori-deep-brown;
    }

    .input-box {
        background: white;
        border-radius: $dotori-border-radius;
        width: 30%;
    }
</style>
