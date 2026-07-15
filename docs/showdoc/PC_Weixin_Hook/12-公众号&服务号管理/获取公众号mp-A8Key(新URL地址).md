# 获取公众号mp-A8Key(新URL地址)

> Source: [https://www.showdoc.com.cn/PCWeixinHook/11559060626863376](https://www.showdoc.com.cn/PCWeixinHook/11559060626863376)  
> ShowDoc page_id: 11559060626863376

##### 简要描述

- 

##### 请求URL
- ` http://{{host}}:{{port}}/MP_Geta8key `
##### 请求方式
- POST

##### 发送示例

```
{
    "url": "https://open.weixin.qq.com/connect/oauth2/authorize?appid=wxca6ee50592b1d6cc&redirect_uri=https%3A%2F%2Fhealth.tengmed.com%2Fapi%2Fmpauth%3Fuserinfo%3D0%26componentid%3Dwx974aab933381604a%26callback%3Dhttps%253A%252F%252Fh5-health.tengmed.com%252Fh5%252Fmobile%252Fhpv%252Fselect%253Ftype%253Dadult%2526cityCode%253D610000%2526cityType%253D2%2526channel%253D0402009%2526hospitalId%253D32243%26key%3Dsnsapi_base&response_type=code&scope=snsapi_base&state=1683277987904&component_appid=wx974aab933381604a#wechat_redirect",
    "value_2": 2, 
    "value_10": 1, 
    "value_18": 0
}


```

##### 发送说明

|参数名|必选|类型|说明|
|:----    |:---|:----- |-----   |
|url |是  |string | 网页地址  |



##### 返回示例
```
{
    "Access_Url": "https://health.tengmed.com/api/mpauth?userinfo=0&componentid=wx974aab933381604a&callback=https%3A%2F%2Fh5-health.tengmed.com%2Fh5%2Fmobile%2Fhpv%2Fselect%3Ftype%3Dadult%26cityCode%3D610000%26cityType%3D2%26channel%3D0402009%26hospitalId%3D32243&key=snsapi_base&code=081ko3Ga1cKFyL0NvFJa1XZjOk3ko3GO&state=1683277987904&appid=wxca6ee50592b1d6cc",
    "Share_Url": "https://open.weixin.qq.com/connect/oauth2/authorize?appid=wxca6ee50592b1d6cc&redirect_uri=https%3A%2F%2Fhealth.tengmed.com%2Fapi%2Fmpauth%3Fuserinfo%3D0%26componentid%3Dwx974aab933381604a%26callback%3Dhttps%253A%252F%252Fh5-health.tengmed.com%252Fh5%252Fmobile%252Fhpv%252Fselect%253Ftype%253Dadult%2526cityCode%253D610000%2526cityType%253D2%2526channel%253D0402009%2526hospitalId%253D32243%26key%3Dsnsapi_base&response_type=code&scope=snsapi_base&state=1683277987904&component_appid=wx974aab933381604a#wechat_redirect"
}
```
