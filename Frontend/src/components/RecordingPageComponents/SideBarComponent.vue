<script setup>
    import {useOpenViduStore} from 'stores/openvidu';
    import {computed, ref} from 'vue';
    import {useRecordingStore} from 'stores/recording';

    const recStore = useRecordingStore();
    const ovstore = useOpenViduStore();

    const props = defineProps({scene: Object, curPage: Number});
    const emit = defineEmits(['moveToPage']);
    const movePage = (page) => {
        // alert('clicked!')
        //방장일 경우만 실행하도록 로직을 추가해야함
        if (ovstore.isHost) {
            ovstore.session.signal({
                    data: page,
                    type: 'page',
                },
            );
        } else alert('방장만 페이지를 이동할 수 있습니다');
        // emit('moveToPage', page);
    };
    const imagesrc = ref(props.scene.backgroundImage);

    const isPageRecorded = computed(() => {
        return recStore.isCurPageRecorded(props.scene.sceneOrder);
    });
</script>

<template>
    <div class=' col-3 q-pr-sm q-pt-sm relative-position hoverpointer' @click='movePage(scene.sceneOrder)'>
        <img :src='scene.backgroundImage' alt='dja' class=' side-img'
             v-bind:class="{ 'side-bar-selected': curPage === scene.sceneOrder, 'side-bar-unselected': curPage !== scene.sceneOrder }" />
        <div class='absolute-top-left q-pa-xs q-mt-sm text-center npsfont side-page-num '
             v-bind:class="{ 'side-bar-selected': curPage === scene.sceneOrder, 'side-bar-unselected': curPage !== scene.sceneOrder }">
            장면 : {{ scene.sceneOrder }}
        </div>
        <!--      녹화가 완료된 장면이면 표시해주자-->
        <div class='absolute-center text-center npsfont rec-fin flex justify-center items-center'
             style='transform:translate(-145px,-86px)'
             v-if='isPageRecorded'></div>
        <div class='absolute-center text-center npsfont rec-fin-text flex justify-center items-center '
             v-if='isPageRecorded'>
            <h6>녹화 완료 </h6>
        </div>
    </div>
</template>

<style scoped>


    .side-img {
        height: 172px;
        width: 280px;
        border-radius: 15px 0px 15px 0px;
    //background: #ffee9a; padding: 4px;
        object-fit: cover;

    }

    .side-page-num {
        background: white;
        height: 3em;
    //width: 3em; color: #6E4E1F; border-radius: 15px 0px 15px 0px;
    }

    .rec-fin {
        background: black;
    //height: 3em; color: white;
        height: 172px;

        width: 280px;
        opacity: 35%;
        border-radius: 15px 0px 15px 0px;
    //width: 3em;

    }

    .rec-fin-text {
        height: 172px;
        width: 280px;;
        border-radius: 15px 0px 15px 0px;
        color: white;
        text-shadow: -1px 0px #000000, 0px 1px #000000, 1px 0px #000000, 0px -1px #000000;
    }

    .side-bar-unselected {
        border: 6px solid #C7A96E;
    }

    .side-bar-selected {
        border: 6px solid #a84d2f;
    }

    .hoverpointer {
        cursor: pointer;

    }

    .side-img:hover {
        transform: scale(1.015);
    }
</style>
