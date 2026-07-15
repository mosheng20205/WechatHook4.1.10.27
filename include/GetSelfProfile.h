#pragma once

namespace httplib { class Server; }

// 注册 /GetSelfProfile/ 接口
void RegisterGetSelfProfile(httplib::Server& svr);

// 注册 /GetContact/ 接口
void RegisterGetContact(httplib::Server& svr);
