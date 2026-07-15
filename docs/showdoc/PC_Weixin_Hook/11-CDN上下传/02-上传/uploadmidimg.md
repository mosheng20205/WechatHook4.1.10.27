# uploadmidimg

> Source: [https://www.showdoc.com.cn/PCWeixinHook/11559060626836688](https://www.showdoc.com.cn/PCWeixinHook/11559060626836688)  
> ShowDoc page_id: 11559060626836688

##### 简要描述

- 

##### 请求URL
- ` http://{{host}}:{{port}}/uploadmidimg `
##### 请求方式
- POST

##### 发送示例

```
{
    "aeskey": "edfa1964dc0e96d3780c8a8ff5d444be",
    "filePath": "C:\\down.jpg",
    "userName": "filehelper",
    "chatType": 5
}
```

##### 发送说明

|参数名|必选|类型|说明|
|:----    |:---|:----- |-----   |
|aeskey |是  |string | 下载后会用到的解密密钥  |



##### 返回示例
```
{
    "data": {
        "data": {
            "aeskey": "edfa1964dc0e96d3780c8a8ff5d444be",
            "encryptfilemd5": "923079f67ae7811439c29c270d236683",
            "filecrc": "483061671",
            "fileid": "3057020100044b304902010002049f6f102602032df98b0204da009324020469d61cac042437663864303230372d666664332d346137392d393334342d3936623564383964373336300204012418020201000405004c4d9b00",
            "filekey": "7f8d0207-ffd3-4a79-9344-96b5d89d7360",
            "filename": "down.jpg",
            "hasbig": "0",
            "hasmid": "1",
            "hasthumb": "1",
            "isgetcdn": "0",
            "isoverload": "0",
            "isretry": "0",
            "rawbigimgsize": "0",
            "rawfilekey": "filehelper_1775639724_1_1",
            "rawfilemd5": "e3f2bb40af56830f4ad276e9d2bc56ff",
            "rawmidimgsize": "576771",
            "rawthumbsize": "15955",
            "rawtotalsize": "576771",
            "recvlen": "576784",
            "retcode": "0",
            "retrysec": "0",
            "seq": "1",
            "thumbheight": "84",
            "thumbwidth": "150",
            "ver": "0",
            "x-ClientIp": "221.179.248.138"
        },
        "desc": "",
        "status": 0
    },
    "ret": 1,
    "retmsg": "success"
}
```
