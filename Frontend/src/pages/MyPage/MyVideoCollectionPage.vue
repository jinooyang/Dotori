<template>
  <headermypage/>
  <q-page class="page-with-margin">
<!--    <div class='text-h5 npsfont q-pl-lg'>보관함</div>-->
<!--    <hr class='q-my-md'>-->
    <div class="q-pa-md">
      <q-table
        style="height: 60vh"
        flat
        :rows="rows"
        :columns="columns"
        row-key="index"
        virtual-scroll
        :rows-per-page-options="[0]"
        class="npsfont"
      >
        <template v-slot:body="props">
          <q-tr :props="props">
            <q-th
              v-for="col in props.cols"
              :key="col.name"
              :props="props"
              style="font-size: 15px"
            >
              <div v-if="col.name === 'preview'">
                  <q-btn outline icon="mdi-play" color="brown" @click="viewMyVideo(`https://dotori.online/${col.value}`)"/>
              </div>
              <div v-else-if="col.name === 'download'">
                <a v-bind:href="`https://dotori.online/api/videos/${col.value}`">
                  <q-btn outline icon="mdi-download-box" color="brown"/>
                </a>
              </div>
              <div v-else>
                {{ col.value }}
              </div>
            </q-th>
          </q-tr>
        </template>
      </q-table>
    </div>

  </q-page>
</template>

<script setup>
  import {localAxios} from 'src/axios/http-commons';
  import {onMounted, ref} from 'vue';
  import Headermypage from 'components/CommonComponents/Headermypage.vue';

  const axios = localAxios()

  const viewMyVideo = (link) => {
    window.open(link, '_blank');
  };

  const columns = [
    {
      name: 'desc',
      required: true,
      label: '책 제목',
      align: 'center',
      headerStyle: 'font-size: 25px',
      field: row => row.bookTitle,
    },
    {name: 'date', align: 'center', label: '날짜', headerStyle: 'font-size: 25px', field: row => row.createdAt},
    {name: 'preview', align: 'center', label: '미리보기', headerStyle: 'font-size: 25px', field: row => row.path},
    {name: 'download', align: 'center', label: '다운로드', headerStyle: 'font-size: 25px', field: row => row.videoId},
  ];
  const rows = ref([]);

  onMounted(async () => {

    axios.get(`/api/members/${sessionStorage.getItem('memberId')}/videos`)
      .then((response) => {
        console.log(response.data)
        rows.value = response.data.videos
        rows.value = rows.value.map(video => {
          const removePath = '/home/ubuntu/dotori-data/'
          video.path = video.path.replace(removePath, '');
          return video;
        });

        rows.value.sort((a, b) => b.videoId - a.videoId);
      })
      .catch((error) =>{
        console.log(error);
      });

  })


</script>

<style lang='scss' scoped>
  .dotori-border {
    border-raius: $dotori-border-radius;
  }

  .card-border-inner {
    background-color: $dotori-light-green;
    border-radius: $dotori-border-radius;
    border: 5px dashed $dotori-light-brown;
  }

  .card-border-outer {
    background-color: $dotori-green;
    border-radius: $dotori-border-radius;

  }
  .page-with-margin {
    margin-top: 90px;
    margin-left : 110px;
    width : 1000px;
  }
</style>
