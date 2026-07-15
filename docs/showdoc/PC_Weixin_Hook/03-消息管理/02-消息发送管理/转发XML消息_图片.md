# 转发XML消息_图片

> Source: [https://www.showdoc.com.cn/PCWeixinHook/11559060626558426](https://www.showdoc.com.cn/PCWeixinHook/11559060626558426)  
> ShowDoc page_id: 11559060626558426

##### 简要描述

- 转发XML消息_图片

##### 请求URL
- ` http://{{host}}:{{port}}/ForwardXMLMsg `
  
##### 请求方式
- POST 

##### 参数

|参数名|必选|类型|说明|
|:----    |:---|:----- |-----   |
|to_wxid |是  |string |发给谁   |
|content |是  |string | xml 内容    |


##### 请求示例 

```
{
    "to_wxid":"filehelper",
    "content":"<?xml version=\"1.0\"?><msg><img aeskey=\"e4c00232809af7909baf4bef341127b0\" encryver=\"1\" cdnthumbaeskey=\"e4c00232809af7909baf4bef341127b0\" cdnthumburl=\"3057020100044b30490201000204ea9587b102032f5dc90204a0fcfa67020469745f3e042430646536346361342d663239312d343565392d623031352d653364646236346161323434020405192a010201000405004c51e500\" cdnthumblength=\"4821\" cdnthumbheight=\"155\" cdnthumbwidth=\"180\" cdnmidheight=\"0\" cdnmidwidth=\"0\" cdnhdheight=\"0\" cdnhdwidth=\"0\" cdnmidimgurl=\"3057020100044b30490201000204ea9587b102032f5dc90204a0fcfa67020469745f3e042430646536346361342d663239312d343565392d623031352d653364646236346161323434020405192a010201000405004c51e500\" length=\"36793\" cdnbigimgurl=\"3057020100044b30490201000204ea9587b102032f5dc90204a0fcfa67020469745f3e042430646536346361342d663239312d343565392d623031352d653364646236346161323434020405192a010201000405004c51e500\" hdlength=\"114358\" md5=\"b8eb60757524c0916ef2758bc87dec97\" hevc_mid_size=\"36793\"><secHashInfoBase64>eyJwaGFzaCI6ImZmMzAxMDUwMTAzMDMwOTAiLCJwZHFoYXNoIjoiOWFkYTM1YWRiYTlhNmI3NTk1OGE0MDU1YmVhYWVhOGJiY2E5NTE1M2FhYTU0MDVjMjBhNzE1NWI0YmY1MTU2YSJ9</secHashInfoBase64><live><duration>0</duration><size>0</size><md5 /><fileid /><hdsize>0</hdsize><hdmd5 /><hdfileid /><stillimagetimems>0</stillimagetimems></live></img><platform_signature /><imgdatahash /><ImgSourceInfo><ImgSourceUrl /><BizType>0</BizType></ImgSourceInfo></msg>"
}
```
