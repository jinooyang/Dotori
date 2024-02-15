<template>
  <q-layout style="position: relative">

    <q-drawer
      show-if-above
      :width='250'
      :breakpoint='400'
      class='my-drawer'
    >

      <q-scroll-area class='scroll-placement light-green-bg'>
        <q-list padding>
          <q-item clickable v-ripple to='/list/books' class="side-bar-menu-bg-white q-mx-sm q-mb-sm" active-class="text-brand">
            <q-item-section avatar>
              <q-icon name='book' />
            </q-item-section>
            <q-item-section>
              <span class="npsfont">책 목록</span>
            </q-item-section>
          </q-item>
          <q-item clickable v-ripple to='/list/rooms' class="side-bar-menu-bg-white q-mx-sm q-mb-sm" active-class="text-brand">
            <q-item-section avatar>
              <q-icon name='room' />
            </q-item-section>

            <q-item-section>
              <span class="npsfont">방 목록</span>
            </q-item-section>
          </q-item>

        </q-list>
      </q-scroll-area>

      <div class='absolute-top light-green-bg profile-placement'>
        <div class='absolute-center bg-transparent column items-center'>
          <div class="profile-bg-white q-my-md">
            <q-avatar size='120px' class=' content-center'>
              <img :src='memberInfo.profileImg' style="object-fit: cover">
            </q-avatar>
          </div>
          <h6 class='npsfont q-ma-none'>{{ memberInfo.nickName }}</h6>
        </div>
      </div>
    </q-drawer>

    <q-page-container>
      <router-view/>
    </q-page-container>
</q-layout>
</template>

<script setup>
import {useOpenViduStore} from 'stores/openvidu';
import {storeToRefs} from 'pinia';
import Header from 'components/CommonComponents/Header.vue';

const openViduStore = useOpenViduStore();
const {memberInfo} = storeToRefs(openViduStore);


</script>

<style lang="scss" scoped>
  $profile-height: 300px;

  .mypagebg {
    width: 100%;
  }

  .side-bar-menu-bg-white {
    background-color: rgba(218, 201, 157, 0.45);
    border-radius: 40px;
  }

  .profile-bg-white {
    background-color: white;
    border-radius: 50%;
    height: 120px;
    width: 120px;
  }

  .base-bg {
    background-color: $dotori-mint;
  }

  //.light-green-bg {
  //  background-color: #C7A96E;
  //}

  .profile-placement {
    height: $profile-height;
    border-right: 2px solid #ddd;
  }

  .scroll-placement {
    height: calc(100% - #{$profile-height});
    margin-top: $profile-height;
    border-right: 2px solid #ddd;
  }
</style>
