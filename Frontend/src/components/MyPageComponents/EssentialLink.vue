<template>
  <q-item clickable tag="div" @click="redirectToPage">
    <q-item-section v-if="icon" avatar>
      <q-icon :name="icon" />
    </q-item-section>

    <q-item-section>
      <q-item-label>{{ title }}</q-item-label>
      <q-item-label caption>{{ caption }}</q-item-label>
    </q-item-section>
  </q-item>
</template>

<script>
import { defineComponent } from 'vue';

export default defineComponent({
  name: 'EssentialLink',
  props: {
    title: {
      type: String,
      required: true,
    },

    caption: {
      type: String,
      default: '',
    },

    to: {
      type: String,
      default: '#',
    },

    icon: {
      type: String,
      default: '',
    },
  },
  methods: {
    redirectToPage() {
      // 여기에서 router.push를 사용하여 새로운 URL 페이지로 이동
      this.$router.push(this.to);
    },
  },
});
</script>
