CREATE TABLE `forgot_password` (
  `user_id` int(11) NOT NULL,
  `alternative_email` varchar(200) NOT NULL,
  `token` varchar(40) DEFAULT NULL,
  `token_expiration` datetime DEFAULT NULL,
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB