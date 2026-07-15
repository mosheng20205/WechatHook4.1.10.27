# 解密dat图片

> Source: [https://www.showdoc.com.cn/PCWeixinHook/11559060626866424](https://www.showdoc.com.cn/PCWeixinHook/11559060626866424)  
> ShowDoc page_id: 11559060626866424

##### 简要描述

- 

##### 请求URL
- ` http://{{host}}:{{port}}/Decode_Pic `
##### 请求方式
- POST

##### 发送示例

```
{
    "src_path":"C:\\Users\\Administrator\\xwechat_files\\wxid_kqism2ws8r7s12_b5dc\\msg\\attach\\0ffee913bf5c72eefc1163c3ef4b51e8\\2026-04\\Img\\433c69609943de3247c0138e7fe79e11.dat",
    "dst_path":"C:\\Users\\Administrator\\xwechat_files\\wxid_kqism2ws8r7s12_b5dc\\temp\\RWTemp\\2026-04\\0ffee913bf5c72eefc1163c3ef4b51e8\\mid.jpg"
}
```

##### 发送说明

|参数名|必选|类型|说明|
|:----    |:---|:----- |-----   |
|src_path |是  |string | 原始dat图片路径  |
|dst_path |是  |string | 转码后的图片保存位置  |


##### 返回示例
```
{

}
```
