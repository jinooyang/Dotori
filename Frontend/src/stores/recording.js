import {onMounted, ref} from 'vue';
import {defineStore} from 'pinia';

export const useRecordingStore
    = defineStore('recordingStore', () => {
    const recHistory = ref(0);//어느어느 페이지가 녹화되었는지 판별하는 비트마스킹용 숫자
    const totalPages = ref(0);
    const updateRecHistory = (newHistory)=>{
        recHistory.value=newHistory;
    }
    const recComplete = (page) => { //특정 페이지 녹화가 성공했을 때
        let x = recHistory.value;
        x = x | (1 << (page - 1));//현재 페이지의 비트를 추가한다
        recHistory.value = x;
    };
    const isCurPageRecorded = (curPage) => {//현재 페이지가 녹화 되었다면 true, 아니면 false를 반환한다
        let res = recHistory.value & (1 << (curPage - 1));
        return res !== 0;
    };
    const checkAllRecComplete = () => {  //모든 페이지가 녹화 성공했으면 true, 아니면 false를 반환한다
        return numberOfRecordedPages() === totalPages.value;
    };

    const numberOfRecordedPages = () => {//몇개의 페이지가 녹화되었는지 확인한다
        let count = 0;
        let number = recHistory.value;
        while (number) {
            count += number & 1;
            number >>= 1;
        }
        return count;
    };
    return {
        recHistory,
        recComplete,
        checkAllRecComplete,
        isCurPageRecorded,
        totalPages,
        numberOfRecordedPages,
        updateRecHistory,

    };
}, {persist: {storage: sessionStorage}});
