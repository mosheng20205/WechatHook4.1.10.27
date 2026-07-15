#include "httplib.h"
#include "json.hpp"
#include <windows.h>
#include <string>
#include <cstring>
#include "global.h"
#include "tools.h"
#include "db_mgr.h"

#include "GetSelfProfile.h"


using json = nlohmann::json;

namespace {

bool ReadProfileInlineString(uintptr_t base, size_t offset, std::string& value)
{
    char buffer[64]{};
    __try {
        std::memcpy(buffer, reinterpret_cast<const void*>(base + offset), sizeof(buffer) - 1);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        value.clear();
        return false;
    }

    const size_t length = strnlen_s(buffer, sizeof(buffer));
    if (length == 0 || length >= sizeof(buffer)) {
        value.clear();
        return false;
    }
    value.assign(buffer, length);
    return true;
}

struct RuntimeProfile {
    std::string accountId;
    std::string nickname;
    std::string phone;
    uint64_t object = 0;
    std::string area;
    std::string signature;
    std::string avatar;
    std::string smallAvatar;
    int sex = 0;
    bool valid = false;
};

void ReadDatabaseProfile(RuntimeProfile& profile)
{
    // The Contact database is owned by a WeChat worker thread.  Do not issue
    // a cross-thread SQLite query from the HTTP handler; leave optional
    // fields empty until a thread-safe profile callback is available.
    (void)profile;
}

RuntimeProfile ReadRuntimeProfile()
{
    RuntimeProfile profile;
    const uintptr_t object = static_cast<uintptr_t>(g_ProfileObject);
    if (!object || !g_IsLogin)
        return profile;

    // WeChat 4.1.10.27: ProfileObject + 0x40 is the profile-data subobject.
    const uintptr_t fields = object + 0x40;
    profile.object = object;
    // Each field stores its length/capacity at the preceding 8-byte slot and
    // the inline UTF-8 bytes at +0x28, +0x48 and +0x68 respectively.
    const bool idOk = ReadProfileInlineString(fields, 0x28, profile.accountId);
    const bool nicknameOk = ReadProfileInlineString(fields, 0x48, profile.nickname);
    const bool phoneOk = ReadProfileInlineString(fields, 0x68, profile.phone);
    profile.valid = idOk || nicknameOk || phoneOk;
    return profile;
}

}


/* =========================
   核心：获取个人资料
   ========================= */



/* =========================
   HTTP 接口
   ========================= */

void RegisterGetSelfProfile(httplib::Server& svr)
{
    svr.Post("/GetSelfProfile", [](const httplib::Request&, httplib::Response& res)
        {
        json resp;

        RuntimeProfile runtime = ReadRuntimeProfile();
        const bool loggedIn = g_IsLogin != 0;
        if (!loggedIn) {
            // Do not return data cached from a previous account/session.
            resp["wxid"] = "";
            resp["alias"] = "";
            resp["nickname"] = "";
            resp["email"] = "";
            resp["qq"] = 0;
            resp["phone"] = "";
            resp["proiv"] = "";
            resp["area"] = "";
            resp["signinfo"] = "";
            resp["avatar"] = "";
            resp["small_avatar"] = "";
            resp["sex"] = 0;
            resp["profile_read_ok"] = false;
            resp["profile_object"] = 0;
            resp["profile_account_id"] = "";
            resp["profile_nickname"] = "";
            resp["profile_phone"] = "";
            res.set_content(resp.dump(), "application/json; charset=utf-8");
            return;
        }
        if (runtime.valid) {
            ReadDatabaseProfile(runtime);
            // The first field is the verified account identifier candidate.
            SelfInfo.wxid = runtime.accountId;
            SelfInfo.alias = runtime.accountId;
            SelfInfo.nickname = runtime.nickname;
            SelfInfo.phone = runtime.phone;
            SelfInfo.area = runtime.area;
            SelfInfo.signinfo = runtime.signature;
            SelfInfo.avatar = runtime.avatar;
            SelfInfo.small_avatar = runtime.smallAvatar;
            SelfInfo.sex = runtime.sex;
        }

        resp["wxid"] = SelfInfo.wxid;
            resp["alias"] = SelfInfo.alias;
            resp["nickname"] = SelfInfo.nickname;
            resp["email"] = SelfInfo.email;
            resp["qq"] = SelfInfo.qq;
            resp["phone"] = SelfInfo.phone;
            resp["proiv"] = SelfInfo.proiv;
            resp["area"] = SelfInfo.area;
        resp["signinfo"] = SelfInfo.signinfo;
        resp["avatar"] = SelfInfo.avatar;
        resp["small_avatar"] = SelfInfo.small_avatar;
        resp["sex"] = SelfInfo.sex;
        resp["profile_read_ok"] = runtime.valid;
        resp["profile_object"] = runtime.object;
        resp["profile_account_id"] = runtime.accountId;
        resp["profile_nickname"] = runtime.nickname;
        resp["profile_phone"] = runtime.phone;
            
            res.set_content(resp.dump(), "application/json; charset=utf-8");
        });
}

void RegisterGetContact(httplib::Server& svr)
{
    svr.Post("/GetContact", [](const httplib::Request& req, httplib::Response& res)
        {
            json resp;
            json request;
            try {
                request = json::parse(req.body.empty() ? "{}" : req.body);
            } catch (...) {
                resp["status"] = -400;
                resp["msg"] = "invalid json";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }

            const std::string wxid = request.value("wxid", "");
            if (wxid.empty() || wxid.size() > 512 ||
                wxid.find('\0') != std::string::npos ||
                wxid.find('\r') != std::string::npos ||
                wxid.find('\n') != std::string::npos) {
                resp["status"] = -400;
                resp["msg"] = "wxid is required";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }
            if (!g_IsLogin) {
                resp["status"] = -401;
                resp["msg"] = "微信未登录";
                res.set_content(resp.dump(), "application/json; charset=utf-8");
                return;
            }

            // Queue the query to the thread that is currently using the
            // captured SQLite connection.  The HTTP worker never touches the
            // connection directly.
            std::string resultJson;
            if (!RunContactQueryOnSqliteThread(wxid, resultJson, 15000)) {
                resp["status"] = -504;
                resp["msg"] = "contact query timed out waiting for WeChat database thread";
                resp["wxid"] = wxid;
                resp["sqlite_last_db_handle"] = g_SqliteLastDbHandle;
                resp["sqlite_last_db_thread"] = g_SqliteLastDbThreadId;
                resp["sqlite_contact_db_handle"] = g_SqliteContactDbHandle;
                res.set_content(resp.dump(4, ' ', false), "application/json; charset=utf-8");
                return;
            }
            try {
                resp = json::parse(resultJson);
            } catch (...) {
                resp["status"] = -505;
                resp["msg"] = "invalid contact query response";
                res.set_content(resp.dump(4, ' ', false), "application/json; charset=utf-8");
                return;
            }
            const int dbStatus = resp.value("status", -1);
            if (dbStatus != 0) {
                resp["msg"] = resp.value("desc", "contact query failed");
                resp["wxid"] = wxid;
                res.set_content(resp.dump(4, ' ', false), "application/json; charset=utf-8");
                return;
            }
            if (!resp.contains("data") || !resp["data"].is_array() ||
                resp["data"].empty() || !resp["data"][0].is_object()) {
                resp = { {"status", 404}, {"msg", "contact not found"}, {"wxid", wxid} };
                res.set_content(resp.dump(4, ' ', false), "application/json; charset=utf-8");
                return;
            }
            resp = resp["data"][0];
            resp["status"] = 0;
            resp["contact_found"] = true;
            resp["wxid"] = wxid;
            if (resp.contains("ImgBuf") && resp["ImgBuf"].is_string() &&
                resp["ImgBuf"].get<std::string>().size() > 16384) {
                resp["ImgBuf"] = "";
                resp["ImgBufTruncated"] = true;
            }
            res.set_content(resp.dump(4, ' ', false), "application/json; charset=utf-8");
        });
}
