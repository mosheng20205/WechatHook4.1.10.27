# 转发XML消息_GIF

> Source: [https://www.showdoc.com.cn/PCWeixinHook/11559060626558429](https://www.showdoc.com.cn/PCWeixinHook/11559060626558429)  
> ShowDoc page_id: 11559060626558429

##### 简要描述

- 转发XML消息_GIF

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
    "content":"<?xml version=\"1.0\"?><msg><emoji md5=\"197f882b6093932edad19c8ab0491cfe\" type=\"2\" len=\"62626\" width=\"228\" height=\"248\"/><gameext type=\"0\" content=\"0\"/></msg>"
}
```
