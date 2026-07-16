#pragma once

#include <cstddef>
#include <string>

namespace httplib { class Server; }

// 注册 /GetSelfProfile/ 接口
void RegisterGetSelfProfile(httplib::Server& svr);

// 注册 /GetContact/ 接口
void RegisterGetContact(httplib::Server& svr);

// 注册 /GetContacts/ 全量联系人快照接口。快照只读取已由微信自身响应
// 或 SQLite Hook 捕获并缓存的记录，不会在 HTTP 线程操作微信内部数据库。
void RegisterGetContacts(httplib::Server& svr);

// 由联系人同步 Hook 调用，用于把已验证的联系人记录放入有界缓存。
void RecordCapturedContactRow(const std::string& wxid, const std::string& rowJson);
