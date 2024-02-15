<template>
  <q-page class="custom-padding">
  <headerbooklist/>
  <div class='row q-mb-md'>
    <div class='search row flex justify-center items-center' style='width: 100%;'>
      <q-input
        class=''
        standout rounded dense placeholder='검색'
        bg-color='white'
        :text-color="'black'"
        style='width: 50%; border: rgba(218, 201, 157, 0.87) solid 3.5px; border-radius: 50px;'
        v-model="searchQuery"
        @keyup.enter="search"
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
        @click="search"
      />
    </div>
  </div>

    <q-page class="page-container">
      <div class='row q-col-gutter-x-md q-col-gutter-y-md'>
        <div v-for='(book,index) in books' :key='book.bookId' class='col-3 q-pa-md'>
          <div class="book-container" @mouseover="showModal(book)" @mouseleave="hideModal">
              <Book class='book-component' :bookdetail="book"></Book>
              <!-- 모달 내용 -->
  <!--            <q-card class="my-card modal-left" v-if="selectedBook === book">-->
  <!--              <q-card-section>-->
  <!--                <div class="text-h7 npsfont">연극을 하려면</div>-->
  <!--                <div class="text-h7 npsfont">{{ book.roleCnt }} 명의 친구들이 필요해요!</div>-->
  <!--              </q-card-section>-->
  <!--            </q-card>-->
          </div>
        </div>
      </div>
    </q-page>
  </q-page>
</template>

<script>
  import {onMounted, ref} from 'vue';
  import Book from 'components/ListPageComponents/Book.vue';
  import {localAxios} from 'src/axios/http-commons';
  import Headerbooklist from 'components/CommonComponents/Headerbooklist.vue';

  const axios = localAxios();
  export default {
    components: {Headerbooklist, Book},
    setup() {
      const books = ref([]);
      const selectedBook = ref(null);
      const searchQuery = ref('')

      onMounted(() => {
        fetchBooks();
      });

      const fetchBooks = async () => {
        try {
          const response = await axios.get('/api/books', { withCredentials: true });
          console.log('API Response:', response);
          books.value = response.data.books;
        } catch (error) {
          console.error('Error fetching books:', error);
        }
      };

      const search = () => {
        books.value = books.value.filter(book => {
          return book.title.includes(searchQuery.value);
        });
      };

      const showModal = (book) => {
        selectedBook.value = book;
      };

      const hideModal = () => {
        selectedBook.value = null;
      };

      return {
        books,
        dialog: ref(false),
        maximizedToggle: ref(true),
        selectedBook,
        showModal,
        hideModal,
        searchQuery,
        search,
      };
    },
  };
</script>

<style lang='scss' scoped>

  .book-wrapper {
    position: relative;
    width: 100%;
    height: 100%;
  }
  .page-container {
    margin-top: 30px;
    margin-left : 30px;

  }
  .book-container {
    position: relative;
  }
  .book-container:hover {
  }
  .book-component:hover {
    transform: scale(1.1); /* 1.1 배 확대 */
    transition: transform 0.3s ease;
  }

  .modal-left {
      position: absolute;
      z-index: 9999;
      bottom:10px;
      top: calc(10% + 10px);
      left: calc(0% + 0px);
      width: 280px; /* 모달의 너비 */
      height: 80px; /* 모달의 높이 */
      background-color: #6fe286;
      padding: 10px;
      border: 1px solid #ccc;
      border-radius: 30px; /* 테두리를 둥글게 만듭니다. */
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
  }
</style>
