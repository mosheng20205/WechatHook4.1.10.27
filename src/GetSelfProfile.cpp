#include "httplib.h"
#include "json.hpp"
#include <windows.h>
#include <string>
#include <cstring>
#include "global.h"
#include "tools.h"

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
    bool valid = false;
};

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

        const RuntimeProfile runtime = ReadRuntimeProfile();
        if (runtime.valid) {
            // The first field is the verified account identifier candidate.
            SelfInfo.wxid = runtime.accountId;
            SelfInfo.alias = runtime.accountId;
            SelfInfo.nickname = runtime.nickname;
            SelfInfo.phone = runtime.phone;
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
        resp["profile_read_ok"] = runtime.valid;
        resp["profile_object"] = runtime.object;
        resp["profile_account_id"] = runtime.accountId;
        resp["profile_nickname"] = runtime.nickname;
        resp["profile_phone"] = runtime.phone;
            
            res.set_content(resp.dump(), "application/json");
        });
}
