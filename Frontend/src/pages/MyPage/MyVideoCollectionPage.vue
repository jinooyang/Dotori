<template>
  <q-page>
    <div class='text-h3 npsfont q-pl-lg'>보관함</div>
    <hr class='q-my-md'>
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
              <div v-if="col.name !== 'videoId'">
                {{ col.value }}
              </div>
              <div v-else>
                <a v-bind:href="`https://dotori.online/api/videos/${col.value}`">
                  <q-btn outline icon="mdi-download-box" color="brown"/>
                </a>
              </div>
            </q-th>
          </q-tr>
        </template>
      </q-table>
    </div>

  </q-page>
</template>

<script setup>
  import {useOpenViduStore} from 'stores/openvidu';
  import {localAxios} from 'src/axios/http-commons';
  import {onMounted, ref} from 'vue';

  const axios = localAxios()

  const columns = [
    {
      name: 'desc',
      required: true,
      label: '책 제목',
      align: 'center',
      headerStyle: 'font-size: 30px',
      field: row => row.bookTitle,
    },
    {name: 'date', align: 'center', label: '날짜', headerStyle: 'font-size: 30px', field: row => row.createdAt},
    {name: 'videoId', align: 'center', label: '다운로드', headerStyle: 'font-size: 30px', field: row => row.videoId},
  ];
  const rows = ref([]);

  onMounted(async () => {
    axios.get(`/api/members/${sessionStorage.getItem('memberId')}/videos`)
      .then((response) => {
        console.log(response.data)
        rows.value = response.data.videos
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

</style>
