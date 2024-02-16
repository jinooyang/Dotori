-- MySQL dump 10.13  Distrib 8.0.32, for Linux (x86_64)
--
-- Host: localhost    Database: dotori
-- ------------------------------------------------------
-- Server version	8.0.32

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `avatar`
--

DROP TABLE IF EXISTS `avatar`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `avatar` (
  `avatar_id` bigint NOT NULL AUTO_INCREMENT,
  `name` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `path` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `member_id` bigint NOT NULL,
  PRIMARY KEY (`avatar_id`),
  UNIQUE KEY `UK_ln8rcc6vgs1umxuc1jmx835gk` (`path`),
  KEY `FK19gyayk5srtmmrwft2cu1rr0v` (`member_id`),
  CONSTRAINT `FK19gyayk5srtmmrwft2cu1rr0v` FOREIGN KEY (`member_id`) REFERENCES `member` (`member_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `avatar`
--

LOCK TABLES `avatar` WRITE;
/*!40000 ALTER TABLE `avatar` DISABLE KEYS */;
/*!40000 ALTER TABLE `avatar` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `book`
--

DROP TABLE IF EXISTS `book`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `book` (
  `book_id` bigint NOT NULL AUTO_INCREMENT,
  `author` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `book_img` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `role_cnt` int DEFAULT NULL,
  `title` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `summary` varchar(300) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`book_id`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `book`
--

LOCK TABLES `book` WRITE;
/*!40000 ALTER TABLE `book` DISABLE KEYS */;
INSERT INTO `book` VALUES (1,'저자 미상','http://localhost/images/books/rabbit-and-turtle.png',3,'토끼와 거북이','\'토끼와 거북이\'는 꾸준함과 인내의 중요성을 가르쳐주는 유명한 동화입니다. 토끼는 자신의 빠른 속도를 자랑하며 거북이를 무시했습니다. 그래서 거북이는 토끼에게 경주를 제안합니다. 토끼는 자신의 승리를 너무 확신하여 중간에 쉬었고, 그 사이에 거북이는 천천히 그러나 꾸준히 앞으로 나아갔습니다. 토끼가 깨어났을 때, 거북이는 이미 결승선을 통과했습니다. 이 동화는 \'빠르게 달리는 것이 항상 승리를 의미하지 않으며, 꾸준히 노력하는 것이 결국에는 성공으로 이어진다\'는 교훈을 전해줍니다.'),(2,'이솝','http://localhost/images/books/lion-and-rat.png',3,'사자와 생쥐','\'사자와 생쥐\'는 이솝우화에서 가장 유명한 이야기 중 하나입니다. 한 번, 사자가 생쥐를 잡아먹으려 했지만, 생쥐는 자신이 나중에 사자를 도울 수 있을 것을 약속하며 목숨을 구걸했습니다. 사자는 웃으며 생쥐를 놓아주었습니다. 시간이 흘러 사자가 사냥꾼의 그물에 걸려 위험에 처했을 때, 생쥐가 나타나 그물을 갉아먹어 사자를 구해주었습니다. 이 이야기는 \'\'아무리 작고 약해 보이는 존재라도 그 가치를 무시해서는 안 된다\'\'는 교훈을 주며, 서로에게 도움을 줄 수 있는 관계의 중요성을 강조합니다.'),(4,'이솝','http://localhost/images/books/flog-and-cow.jpg',3,'황소와 개구리','준비 중입니다.'),(5,'이솝','http://localhost/images/books/sly-fox.jpg',2,'꾀 많은 여우','준비 중입니다.'),(6,'이솝','http://localhost/images/books/fox-and-grape.jpg',3,'여우와 신 포도','준비 중입니다.'),(7,'이솝','http://localhost/images/books/shepherd-boy.jpg',3,'양치기 소년','준비 중입니다.'),(8,'이솝','http://localhost/images/books/wind-and-sun.jpg',3,'북풍과 태양','준비 중입니다.'),(9,'이솝','http://localhost/images/books/the-ant-and-the-grasshopper.jpg',3,'개미와 베짱이','준비 중입니다.'),(10,'이솝','http://localhost/images/books/belling-the-cat.jpg',4,'고양이 목에 방울달기','준비 중입니다.'),(11,'이솝','http://localhost/images/books/foolish-donkey.jpg',3,'어리석은 당나귀','준비 중입니다.'),(12,'이솝','http://localhost/images/books/wolf-and-young-sheep.jpg',3,'늑대와 어린양','준비 중입니다.'),(13,'이솝','http://localhost/images/books/flying-turtle.jpg',2,'하늘을 날고 싶은 거북이','준비 중입니다.'),(14,'테스트','http://localhost/images/books/test.png',1,'테스트책','테스트'),(15,'저자 미상','http://localhost/images/books/brother-sister-sun-and-moon.png',3,'해와 달이 된 오누이','준비 중입니다.'),(16,'안데르센','http://localhost/images/books/naked-king.png',4,'벌거벗은 임금님','준비 중입니다.'),(17,'저자 미상','http://localhost/images/books/jack-and-bean-tree.png',3,'잭과 콩나무','준비 중입니다.'),(18,'안데르센','http://localhost/images/books/ugly-duckling.png',4,'미운 오리새끼','준비 중입니다.'),(19,'조지프 제이콥스','http://localhost/images/books/three-litte-pigs.png',4,'아기돼지 삼형제','준비 중입니다.'),(20,'저자 미상','http://localhost/images/books/hansel-and-gretel.png',4,'헨젤과 그레텔','준비 중입니다.'),(21,'안데르센','http://localhost/images/books/match-girl.png',3,'성냥팔이 소녀','준비 중입니다.'),(22,'위다','http://localhost/images/books/dog-of-flanders.png',4,'플랜더스의 개','준비 중입니다.'),(23,'저자 미상','http://localhost/images/books/kongji-and-padji.png',4,'콩쥐 팥쥐','준비 중입니다.'),(24,'저자 미상','http://localhost/images/books/gold-ax-and-silver-ax.png',3,'금도끼 은도끼','준비 중입니다.');
/*!40000 ALTER TABLE `book` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `member`
--

DROP TABLE IF EXISTS `member`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `member` (
  `member_id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `nickname` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `profile_img` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'https://dotori.online/images/members/default.png',
  `member_email` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `role` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `social_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `social_type` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `refresh_token` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `room_member_room_member_id` bigint DEFAULT NULL,
  PRIMARY KEY (`member_id`),
  KEY `FK9ylwomjxltvu9h124v6ox9c9t` (`room_member_room_member_id`),
  CONSTRAINT `FK9ylwomjxltvu9h124v6ox9c9t` FOREIGN KEY (`room_member_room_member_id`) REFERENCES `room_member` (`room_member_id`)
) ENGINE=InnoDB AUTO_INCREMENT=85 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `member`
--

LOCK TABLES `member` WRITE;
/*!40000 ALTER TABLE `member` DISABLE KEYS */;
/*!40000 ALTER TABLE `member` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `member_video`
--

DROP TABLE IF EXISTS `member_video`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `member_video` (
  `member_video_id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `book_id` bigint DEFAULT NULL,
  `member_id` bigint NOT NULL,
  `video_id` bigint NOT NULL,
  PRIMARY KEY (`member_video_id`),
  KEY `FKcs5b2umhclusp3awmc7gdgrqi` (`member_id`),
  KEY `FKp627ppn3og0f0endppi9gbgbu` (`video_id`),
  CONSTRAINT `FKcs5b2umhclusp3awmc7gdgrqi` FOREIGN KEY (`member_id`) REFERENCES `member` (`member_id`),
  CONSTRAINT `FKp627ppn3og0f0endppi9gbgbu` FOREIGN KEY (`video_id`) REFERENCES `video` (`video_id`)
) ENGINE=InnoDB AUTO_INCREMENT=47 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `member_video`
--

LOCK TABLES `member_video` WRITE;
/*!40000 ALTER TABLE `member_video` DISABLE KEYS */;
/*!40000 ALTER TABLE `member_video` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `role`
--

DROP TABLE IF EXISTS `role`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `role` (
  `role_id` bigint NOT NULL AUTO_INCREMENT,
  `mask_path` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `name` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `book_id` bigint DEFAULT NULL,
  `mask_thumbnail_path` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`role_id`),
  KEY `FKo6vcoufchqo7kemqqynxorna3` (`book_id`),
  CONSTRAINT `FKo6vcoufchqo7kemqqynxorna3` FOREIGN KEY (`book_id`) REFERENCES `book` (`book_id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `role`
--

LOCK TABLES `role` WRITE;
/*!40000 ALTER TABLE `role` DISABLE KEYS */;
INSERT INTO `role` VALUES (1,'http://localhost/images/characters/rabbit-and-turtle/rabbit.glb','토끼',1,'http://localhost/images/characters/rabbit-and-turtle/rabbit_thumbnail.png'),(2,'http://localhost/images/characters/rabbit-and-turtle/turtle.glb','거북이',1,'http://localhost/images/characters/rabbit-and-turtle/turtle_thumbnail.png'),(3,'','사회자',1,'http://localhost/images/members/default.png'),(4,'http://localhost/images/characters/lion-and-rat/rat.glb','생쥐',2,'http://localhost/images/characters/lion-and-rat/rat_thumbnail.png'),(5,'http://localhost/images/characters/lion-and-rat/lion.glb','사자',2,'http://localhost/images/characters/lion-and-rat/lion_thumbnail.png'),(6,'','사회자',2,'http://localhost/images/members/default.png'),(7,'http://localhost/images/characters/lion-and-rat/rat.glb','테스트_사회자',14,'http://localhost/images/characters/lion-and-rat/rat_thumbnail.png');
/*!40000 ALTER TABLE `role` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `room`
--

DROP TABLE IF EXISTS `room`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `room` (
  `room_id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `host_id` bigint DEFAULT NULL,
  `is_public` bit(1) DEFAULT NULL,
  `is_recording` bit(1) DEFAULT NULL,
  `join_cnt` int DEFAULT NULL,
  `limit_cnt` int DEFAULT NULL,
  `password` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `session_id` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `title` varchar(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `book_id` bigint NOT NULL,
  PRIMARY KEY (`room_id`),
  KEY `FKvokddjbkrl2em84s9hctetmk` (`book_id`),
  CONSTRAINT `FKvokddjbkrl2em84s9hctetmk` FOREIGN KEY (`book_id`) REFERENCES `book` (`book_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1432 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `room`
--

LOCK TABLES `room` WRITE;
/*!40000 ALTER TABLE `room` DISABLE KEYS */;
/*!40000 ALTER TABLE `room` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `room_member`
--

DROP TABLE IF EXISTS `room_member`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `room_member` (
  `room_member_id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `avatar_id` bigint DEFAULT NULL,
  `is_ready` bit(1) DEFAULT NULL,
  `role_id` bigint DEFAULT NULL,
  `member_id` bigint DEFAULT NULL,
  `room_id` bigint DEFAULT NULL,
  PRIMARY KEY (`room_member_id`),
  KEY `FKav1svcloqr7ue4dhsgkj5t4a5` (`member_id`),
  KEY `FKlmp67erahqx7u5shbkc12p0lw` (`room_id`),
  CONSTRAINT `FKav1svcloqr7ue4dhsgkj5t4a5` FOREIGN KEY (`member_id`) REFERENCES `member` (`member_id`),
  CONSTRAINT `FKlmp67erahqx7u5shbkc12p0lw` FOREIGN KEY (`room_id`) REFERENCES `room` (`room_id`)
) ENGINE=InnoDB AUTO_INCREMENT=676 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `room_member`
--

LOCK TABLES `room_member` WRITE;
/*!40000 ALTER TABLE `room_member` DISABLE KEYS */;
/*!40000 ALTER TABLE `room_member` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `scene`
--

DROP TABLE IF EXISTS `scene`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scene` (
  `scene_id` bigint NOT NULL AUTO_INCREMENT,
  `background_image` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `scene_order` int DEFAULT NULL,
  `book_id` bigint NOT NULL,
  PRIMARY KEY (`scene_id`),
  KEY `FKt4t7bx5ox89ig3q5vbysubsvn` (`book_id`),
  CONSTRAINT `FKt4t7bx5ox89ig3q5vbysubsvn` FOREIGN KEY (`book_id`) REFERENCES `book` (`book_id`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `scene`
--

LOCK TABLES `scene` WRITE;
/*!40000 ALTER TABLE `scene` DISABLE KEYS */;
INSERT INTO `scene` VALUES (1,'http://localhost/images/scenes/rabbit-and-turtle/scene_1.png',1,1),(2,'http://localhost/images/scenes/rabbit-and-turtle/scene_2.png',2,1),(3,'http://localhost/images/scenes/rabbit-and-turtle/scene_3.png',3,1),(4,'http://localhost/images/scenes/rabbit-and-turtle/scene_4.png',4,1),(5,'http://localhost/images/scenes/rabbit-and-turtle/scene_5.png',5,1),(6,'http://localhost/images/scenes/rabbit-and-turtle/scene_6.png',6,1),(7,'http://localhost/images/scenes/rabbit-and-turtle/scene_7.png',7,1),(8,'http://localhost/images/scenes/rabbit-and-turtle/scene_8.png',8,1),(9,'http://localhost/images/scenes/rabbit-and-turtle/scene_9.png',9,1),(10,'http://localhost/images/scenes/rabbit-and-turtle/scene_10.png',10,1),(11,'http://localhost/images/scenes/lion-and-rat/scene_1.png',1,2),(12,'http://localhost/images/scenes/lion-and-rat/scene_2.png',2,2),(13,'http://localhost/images/scenes/lion-and-rat/scene_3.png',3,2),(14,'http://localhost/images/scenes/lion-and-rat/scene_4.png',4,2),(15,'http://localhost/images/scenes/lion-and-rat/scene_5.png',5,2),(16,'http://localhost/images/scenes/lion-and-rat/scene_6.png',6,2),(17,'http://localhost/images/books/test.png',1,14);
/*!40000 ALTER TABLE `scene` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `scene_video`
--

DROP TABLE IF EXISTS `scene_video`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `scene_video` (
  `scene_video_id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `path` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `scene_order` int DEFAULT NULL,
  `room_id` bigint NOT NULL,
  PRIMARY KEY (`scene_video_id`),
  KEY `FK1ftayo16j5mjvgebgpo5ndt2h` (`room_id`),
  CONSTRAINT `FK1ftayo16j5mjvgebgpo5ndt2h` FOREIGN KEY (`room_id`) REFERENCES `room` (`room_id`)
) ENGINE=InnoDB AUTO_INCREMENT=202 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `scene_video`
--

LOCK TABLES `scene_video` WRITE;
/*!40000 ALTER TABLE `scene_video` DISABLE KEYS */;
/*!40000 ALTER TABLE `scene_video` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `script`
--

DROP TABLE IF EXISTS `script`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `script` (
  `script_id` bigint NOT NULL AUTO_INCREMENT,
  `content` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `script_order` int DEFAULT NULL,
  `role_id` bigint NOT NULL,
  `scene_id` bigint NOT NULL,
  PRIMARY KEY (`script_id`),
  KEY `FKlv4inwfdmtc1xg16ju3gg5o9i` (`role_id`),
  KEY `FKl9tlxsl8ra8aj4oif37ruhdxm` (`scene_id`),
  CONSTRAINT `FKl9tlxsl8ra8aj4oif37ruhdxm` FOREIGN KEY (`scene_id`) REFERENCES `scene` (`scene_id`),
  CONSTRAINT `FKlv4inwfdmtc1xg16ju3gg5o9i` FOREIGN KEY (`role_id`) REFERENCES `role` (`role_id`)
) ENGINE=InnoDB AUTO_INCREMENT=55 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `script`
--

LOCK TABLES `script` WRITE;
/*!40000 ALTER TABLE `script` DISABLE KEYS */;
INSERT INTO `script` VALUES (1,'토끼 : 또 뭉그적대고 있구나. 하기야 저 우스꽝스럽고 짤따란 다리로 짤짤거리고 다니는 것만 해도 다행이지.\n',1,1,1),(2,'사회자 : 토끼가 거북이의 느린 걸음을 깔보았어요. 거북이가 토끼에 말했어요',2,3,1),(3,'거북이 : 나는 지금이 좋아. 느린 걸음으로도 너랑 달리기 시합을 해서 이길 수 있는데, 왜 빠른 걸음을 원하겠어?\n',3,2,1),(4,'사회자 : 토끼가 배를 잡고 웃었어요.',1,3,2),(5,'토끼 : 하하하, 나랑 달리기 시합을 해서 이길 수 있다고! 너 정말이야? 혹시 살짝 돌아 버린 것은 아니겠지?',2,1,2),(6,'사회자 : 거북이가 대답했어요.',3,3,2),(7,'거북이 : 기는 놈 위에 나는 놈 있는 거야. 길고 짧은 것은 대어 보아야 아는 거고.',4,2,2),(8,'거북이 : 너도 숲 속 마을에 사는 여우랑 친하지. 경주로와 결승선을 정해 달라고 부탁하면 어떨까?\n',1,2,3),(9,'사회자 : 토끼가 어리둥절한 눈으로 거북이를 쳐다보았어요.\n',2,3,3),(10,'토끼 : 으응, 그러지 뭐. 날짜는?\n',3,1,3),(11,'거북이 : 내일모레 어떨까?\n',4,2,3),(12,'사회자 : 거북이 말에 토끼가 고개를 끄덕였어요.\n',5,3,3),(13,'사회자 : 시합 날이 밝았고 출발 신호와 함께 달리기 시합이 시작되었어요. 토끼가 번개처럼 뛰쳐나갔어요. ',1,3,4),(14,'토끼 : 빨리 시합을 끝내고 거북이를 실컷 놀려 준 다음 한숨 푹 자야지. 근데 오늘따라 유난히 덥네.',2,1,4),(15,'사회자 : 언덕에 도착한 토끼는 숨을 헉헉거리며 걸음을 멈추었어요.',1,3,5),(16,'토끼 : 잠깐 쉬었다 가야겠다. 느려 터진 그 친구는 아직 숲길에도 들어서지 못했을걸.',2,1,5),(18,'사회자 : 토끼가 나무에 등을 기댔어요. 바람이 살랑살랑 불어와 기분 좋게 털 사이를 간질여 주었어요.\n',1,3,6),(19,'토끼 : 이야, 시원하다! 아이, 편하다!\n',2,1,6),(20,'사회자 : 토끼의 동그란 눈이 사르륵 감겼어요. 깜빡 잠이 들어 버렸지요.\n',3,3,6),(21,'사회자 : 한편 거북이는 잠시도 한눈팔지 않고 부지런히 걸음을 옮겼어요. \n',1,3,7),(22,'사회자 : 땀이 비 오듯 줄줄 흐르고, 자리에 앉아서 쉬고 싶은 마음이 굴뚝같았어요.\n',2,3,7),(23,'거북이 : 안 돼! 여기서 물러날 수는 없어. 끝까지 최선을 다할 테야!',3,2,7),(24,'사회자 : 거북이는 사방이 확 트인 언덕 꼭대기에 올라섰어요. 느림보 거북이의 승리였어요!\n',1,3,8),(25,'거북이 : 내가 이겼다!\n',2,2,8),(27,'사회자 : 잠에서 깬 토끼는 뒤늦게 도착하여 울었습니다.\n',1,3,9),(28,'토끼 : 억울해! 내가 이긴건데!  \n',2,1,9),(29,'거북이 : 너가 여유를 부릴동안 나는 최선을 다했어. 포기하지 않고 끝까지 노력한 덕분에 이길 수 있었어.\n',3,2,9),(31,'토끼 : 너를 무시해서 미안해. 나도 앞으로는 꾸준히 노력하는 자세를 갖도록 할게\n',1,1,10),(32,'거북이 : 그래. 우리 함께 노력하자.\n',2,2,10),(33,'사회자 : 토끼는 거북이를 무시한 것을 사과하고, 거북이는 사과를 받아주며 둘은 화해를 하게 되었습니다.\n',3,3,10),(34,'사회자 : 곤히 코를 골던 사자가 어흥 소리를 지르며 벌떡 일어났어요. \n',1,6,11),(35,'사회자 : 달리던 생쥐가 잠자는 사자의 코털을 건드렸지요.\n',2,6,11),(36,'사회자 : 생쥐가 부들부들 떨며 손이 발이 되도록 빌었어요.\n',1,6,12),(37,'생쥐 : 사자님, 제발 살려 주세요! 하늘이 무너져 내려도, 절대 그 은혜를 잊지 않고 꼭 보답하겠어요!\n',2,4,12),(38,'사자 : 후.. 그래. 너같이 작은 것은 먹어도 간에 기별도 안가겠다.\n',3,5,12),(39,'사회자 : 사자는 생쥐를 그냥 놓아주었어요. \n',1,6,13),(40,'생쥐 : 감사합니다, 사자님! 이 은혜는 잊지 않을게요!\n',2,4,13),(41,'사회자 : 생쥐는 연방 허리 숙여 감사의 인사를 하고, 수풀 사이로 쪼르르 달아났어요.\n',3,6,13),(42,'사회자 : 얼마 후, 사자는 숲속을 걷다 사냥꾼들이 설치한 그물에 걸리게 되었어요.\n',1,6,14),(43,'사회자 : 녹초가 되어 발만 꼼지락거리는데, 어디선가 사각사각 사과 씹는 듯한 소리가 들렸어요.\n',3,6,14),(44,'사회자 : 위에 올라앉은 것은 지난번에 먹는 것도 귀찮아 놓아준 생쥐였어요.\n',1,6,15),(45,'생쥐 : 사자님! 조금만 기다리세요! 제가 구해드릴게요!\n',2,4,15),(46,'사회자 : 생쥐가 죽을힘을 다해 이빨로 그물을 갉았어요.  마침내 그물이 터지고, 사자가 풀려났어요.\n',3,6,15),(47,'생쥐 : 사자님, 안녕하세요!',1,4,16),(48,'사자 : 안녕, 생쥐야. 뭐라고 말해야할지 모르겠구나.',2,5,16),(49,'생쥐 : 에이, 그럴 때는 그냥 ‘고마워!’ 하면 되는 거예요!\n',3,4,16),(50,'사자 : 고맙다',4,5,16),(51,'사회자 : 사자는 생쥐에게 진심으로 사과를 했고, 둘은 좋은 친구가 되었답니다.\n',5,6,16),(52,'테스트',1,7,17),(53,'사자 : 어떤 놈이 내 단잠을 깨우는거야!',3,5,11),(54,'사자 : 으아악! 사자 살려!',2,5,14);
/*!40000 ALTER TABLE `script` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `video`
--

DROP TABLE IF EXISTS `video`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `video` (
  `video_id` bigint NOT NULL AUTO_INCREMENT,
  `created_at` datetime(6) DEFAULT NULL,
  `updated_at` datetime(6) DEFAULT NULL,
  `path` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`video_id`)
) ENGINE=InnoDB AUTO_INCREMENT=28 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `video`
--

LOCK TABLES `video` WRITE;
/*!40000 ALTER TABLE `video` DISABLE KEYS */;
/*!40000 ALTER TABLE `video` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-02-16 10:22:21
