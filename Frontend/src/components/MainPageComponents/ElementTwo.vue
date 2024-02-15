<template>
  <!--  <hr style='border: solid yellow 3px' />-->
  <div class='row'>

    <h2 class='npsfont q-mx-lg q-mt-lg q-mb-none col-10 offset-2' style='color: #282828'>왜 '도토리'여야 하나요?</h2>
    <h5 class='npsfont q-mx-lg q-mt-sm q-mb-none col-10 offset-2' style='color: #282828'>2. 친구들과 함께 놀고 싶은 아이들에게,<br />
      함께 하는 즐거움을 선물합니다.</h5>
    <div class='col-8 offset-2'>
      <div class='row'>
        <div class='col-6 flex justify-center q-mt-lg'>

          <!--          <img src='src/assets/MyPageImages/iupic.jpg'-->
          <!--               width='400px'-->
          <!--               height='400px'-->
          <!--               style='object-fit: cover; border-radius: 25px' />-->
          <div style='width: 400px;height: 400px;' class='relative-position'>
            <div class='absolute-bottom-left flex justify-center items-center'
                 style='transform:translate(-10px,-80px)'>
              <img src='~assets/DotoriImages/jerry2d.png'
                   width='210px'
                   height='210px'
                   style='
                    object-fit: contain;
                    /*border-radius: 50%;*/
                    /*border: 4px solid #00fff7;*/
                    /*padding : 4px;*/
                    /*background-color: #ffeac2;*/
                    '
                   class='q-ma-none q-pa-none ani-l' />
            </div>
            <div class='absolute-bottom-right flex justify-center items-center'
                 style='transform:translate(-50px,-180px)'>
              <img src='~assets/DotoriImages/lion2d.png'
                   width='210px'
                   height='210px'
                   style='object-fit: contain;
                   /*border-radius: 50%;*/
                    /*border: 4px solid #fff100;*/
                    /*padding : 4px;*/
                    /*background-color: #ffeac2;*/
                    ' class='q-ma-none q-pa-none ani-tr' />
            </div>
            <div class='absolute-bottom-right flex justify-center items-center'
                 style='transform:translate(-45px,-20px)'>
              <img src='~assets/DotoriImages/racoon2d.png'
                   width='230px'
                   height='230px'
                   style='
                    object-fit: contain;
                    /*border-radius: 50%;*/
                    /*border: 4px solid #eeadff;*/
                    /*padding : 4px;*/
                    /*background-color: #ffeac2;*/
                    '
                   class='q-ma-none q-pa-none ani-bl' />
            </div>


          </div>
        </div>
        <div class='col-6 flex justify-center items-center'>
          <h4 class='npsfont'>친구들과 함께<br />연극을 시작해봐요!</h4>

        </div>

      </div>

    </div>

  </div>
  <!--  <hr style='border: solid yellow 3px' />-->
</template>

<script setup>

</script>

<style scoped>

</style>
<style>

  .ani-bl {
    animation-name: bl;
    animation-duration: 3s;
    animation-iteration-count: 1000;
    position: relative;
  }

  @keyframes bl {
    0% {
      left: 0px;
      top: 0px;
    }

    50% {
      left: 10px;
      top: 10px;
    }

    100% {
      left: 0px;
      top: 0px;
    }
  }

  .ani-tr {
    animation-name: tr;
    animation-duration: 3s;
    animation-iteration-count: 1000;
    position: relative;
  }

  @keyframes tr {
    0% {
      left: 0px;
      top: 0px;
    }

    50% {
      left: 15px;
      top: -15px;
    }

    100% {
      left: 0px;
      top: 0px;
    }
  }

  .ani-l {
    animation-name: example;
    animation-duration: 3s;
    animation-iteration-count: 1000;
    position: relative;
  }

  @keyframes example {
    0% {
      left: 0px;
      top: 0px;
    }

    50% {
      left: -20px;
      top: 0px;
    }

    100% {
      left: 0px;
      top: 0px;
    }
  }

</style>
