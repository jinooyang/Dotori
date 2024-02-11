<template>
  <q-page padding>

    <div class='row q-mb-md'>

      <div class='search row flex justify-center items-center' style='width: 100%;'>
        <q-input
          class=''
          standout rounded dense placeholder='검색'
          color='black' bg-color='white'
          style='width: 50%; border: #C7A96E solid 5px; border-radius: 50px; '
        >
        </q-input>
        <q-btn
          class=''
          icon='search'
          round
          size='lg'
          flat
          unelevated
          style='color: #C7A96E; font-weight: bolder'
        />
      </div>
    </div>

    <div class='row q-col-gutter-x-md q-col-gutter-y-md'>
      <div v-for='book in books' :key='book.bookId' class='col-12 col-sm-6 col-md-4 col-lg-3 q-pa-md'>
        <Book :bookdetail="book"></Book>
      </div>
    </div>
  </q-page>
</template>

<script>
  import {onMounted, ref} from 'vue';
  import Book from 'components/ListPageComponents/Book.vue';
  import {localAxios} from 'src/axios/http-commons';

  const axios = localAxios();
  export default {
    components: {Book},
    setup() {
      const books = ref([]);

      onMounted(() => {
        fetchBooks();
      });

      const fetchBooks = async () => {
        try {
          const response = await axios.get('/api/books',{withCredentials: true});
          console.log('API Response:', response);
          books.value = response.data.books;
        } catch (error) {
          console.error('Error fetching books:', error);
        }
      };

      return {
        books,
        dialog: ref(false),
        maximizedToggle: ref(true),
      };
    },
  };
</script>

<style lang='scss' scoped>

</style>
