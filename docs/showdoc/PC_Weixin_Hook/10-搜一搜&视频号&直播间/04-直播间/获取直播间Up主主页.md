# 获取直播间Up主主页

> Source: [https://www.showdoc.com.cn/PCWeixinHook/11559060626866397](https://www.showdoc.com.cn/PCWeixinHook/11559060626866397)  
> ShowDoc page_id: 11559060626866397

##### 简要描述

- 

##### 请求URL
- ` http://{{host}}:{{port}}/h5exttransfer `
##### 请求方式
- POST

##### 发送示例

```
{
    "requrl":"/cgi-bin/micromsg-bin/pc_finderuserpage",
    "reqJson": "{\"finder_basereq\":{\"userver_for_h5\":12,\"request_id\":\"1774342691827862576\",\"scene\":143,\"ctx_info\":{\"context_id\":\"32-20-140-W24ac90572c82b0161774342643067\",\"client_report_buff\":\"{\\\"entranceId\\\":\\\"1001\\\"}\"}},\"username\":\"v2_060000231003b20faec8c4e6881ec2dcca01e436b07776c69c66feb737e614348a628f5fa901@finder\",\"object_id\":\"0\",\"finder_username\":\"v2_060000231003b20faec8c6e18c1fcad5cb01ea31b077addc0e586f1e6479e820374a502dfc5a@finder\",\"last_buffer\":\"CLuxgP/G77bGzgEQARgAILSxsJTY0dvHzgEgubGMy87K1MfOASCZsdjKz5DOx84BILCx0Onk7MbHzgEgvrHgzOv9v8fOASCnsZCjiLq5x84BIJixiKupsavHzgEgsLGk+qLCpMfOASC/scyTmu3fxs4BIJqxqLun/tjGzgEgwLHQsrCP0sbOASCcsYCwvKDLxs4BIL2xhLLYscTGzgEgwrGc387CvcbOASC7sYD/xu+2xs4BMAE44c6/zpW4kwNAAA==\",\"need_fans_count\":0}",
    "cgiCmdid": 6624,
    "h5Authtoken":"CAASDDXpL1W9xEQHIXQ9nxoAIgAqdQALMzKUBAAAAQAAAAAAM/qXPSw6ToGtH9dQwmkgAAAA1UGdBXXRK/g86uSCGsDBfuBITiH/f/+SD7AQwWXuy/r3lkGzAlpqyiJ9wDjbsJ2NArJZZgV4xgG5xUuLiIRRI1OUZ1qe1uRPyXUXbaNZshRlaFh9ig==",
    "h5Url": "https://channels.weixin.qq.com/web/pages/profile?username=v2_060000231003b20faec8c4e6881ec2dcca01e436b07776c69c66feb737e614348a628f5fa901%2540finder&context_id=32-20-140-W24ac90572c82b0161774342643067&entrance_id=1001&reddot_id=1774342638275018_14874133679562164855_2&from_access_id=f7af9b6b-1751-4692-aa9a-c400209aa76d&fpid=FinderFollow&xlab_enable_finder_home=1&preload_id=17461051196133509394&exportkey=n_ChQIAhIQQRr%2FLBxL%2B4UDlzg1b8p%2FKBLtAQIE97dBBAEAAAAAAOTaBPOamCwAAAAOpnltbLcz9gKNyK89dVj0CeKtWg0j0H3q5p8%2BWULcK69srGww4EZxDuGxYkF0N0j%2BT2dm%2FPXxOz51dxgqJ0VAiLwXHcF49gh8iKcG7ToXDdO8Uc0rk0fnSLIZQ3lwaWIfA%2FzsLYpjBBXzbMiqB4O6%2Fg6FM25IAegJipelitSvL7XhwRIrGQZVpXYaICu9LqRJcseOGT5IzPVsC5DKIXhCf2fxLZSEotDzxZXbAWvHmPua16VSvZu8e5u2gCgERgD1Ir2vPZ6RuSdLE0gKwzwQMLaW%2FIICXA%3D%3D&pass_ticket=cn2Phd%2BYK3eJSkTN9O1Fmsp7UTL2psCI7s3lIB3XD3QvxtfVnWEGtHf0b7CDyFBay90joEO3v6NO2mOCqQgVPw%3D%3D&wx_header=0",
    "scope": "finderLive",
    "needccd": 1
}

```

##### 发送说明

|参数名|必选|类型|说明|
|:----    |:---|:----- |-----   |
|scope |是  |string |   |



##### 返回示例
```
{

}
```
