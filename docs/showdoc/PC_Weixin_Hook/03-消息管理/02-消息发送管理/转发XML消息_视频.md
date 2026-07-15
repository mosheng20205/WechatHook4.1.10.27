# 转发XML消息_视频

> Source: [https://www.showdoc.com.cn/PCWeixinHook/11559060626558428](https://www.showdoc.com.cn/PCWeixinHook/11559060626558428)  
> ShowDoc page_id: 11559060626558428

##### 简要描述

- 转发XML消息_视频

##### 请求URL
- ` http://{{host}}:{{port}}/ForwardXMLMsg `
  
##### 请求方式
- POST

##### 参数

|参数名|必选|类型|说明|
|:----    |:---|:----- |-----   |
|to_wxid |是  |string |发给谁   |
|content |是  |string | xml 内容    |


##### 发送示例

```
{
    "to_wxid":"filehelper",
    "content":"<?xml version=\"1.0\"?><msg><videomsg aeskey=\"42a47ed66f19f5c6ad033ad881d2a022\" cdnvideourl=\"3057020100044b30490201000204bcc1a38502032f8411020427ba587d0204694d0228042437633933626134372d313861312d346263372d393862622d6661393664373232393434320204091808040201000405004c54a100\" cdnthumbaeskey=\"42a47ed66f19f5c6ad033ad881d2a022\" cdnthumburl=\"3057020100044b30490201000204bcc1a38502032f8411020427ba587d0204694d0228042437633933626134372d313861312d346263372d393862622d6661393664373232393434320204091808040201000405004c54a100\" length=\"698109\" playlength=\"7\" cdnthumblength=\"4743\" cdnthumbwidth=\"224\" cdnthumbheight=\"398\" fromusername=\"wxid_qer9pi8b6vm822\" md5=\"0b0c58563d6f6d67d0da2ed2c2f43b42\" newmd5=\"7a5c1cf6b435295bc67ce7c65a1dff7b\" isplaceholder=\"0\" rawmd5=\"\" rawlength=\"0\" cdnrawvideourl=\"\" cdnrawvideoaeskey=\"\" overwritenewmsgid=\"0\" originsourcemd5=\"ad5903a3a5c21b09679a4d060226e3c3\" isad=\"0\" /></msg>"
}
```
