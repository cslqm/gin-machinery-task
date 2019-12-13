DROP DATABASE `cslqm_cslqm_cslqm_cslqm_task_svr`;

CREATE DATABASE `cslqm_cslqm_cslqm_cslqm_task_svr`;

use cslqm_cslqm_cslqm_cslqm_task_svr;

CREATE TABLE `task_svr_user` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL UNIQUE COMMENT '账号',
  `password` varchar(50) DEFAULT '' COMMENT '密码',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE `task_svr_task` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `task_name` varchar(100) DEFAULT '' COMMENT '任务名',
  `content` text,
  `created_on` int(11) DEFAULT NULL,
  `created_by` varchar(50) NOT NULL COMMENT '创建人',
  `modified_on` int(11) DEFAULT NULL,
  `state` tinyint(3) unsigned DEFAULT '1',
  `task_uuid` varchar(50) DEFAULT '' COMMENT '任务队列uuid',
  `task_log` text,
  PRIMARY KEY (`id`),
  KEY `created_by` (`created_by`),
  CONSTRAINT `task_1` FOREIGN KEY (`created_by`) REFERENCES `task_svr_user` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='任务管理';

INSERT INTO `cslqm_cslqm_cslqm_cslqm_task_svr`.`task_svr_user` (`id`, `username`, `password`) VALUES (null, 'test', 'test123456');
