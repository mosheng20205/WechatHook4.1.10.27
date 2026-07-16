#include "httplib.h"
#include "json.hpp"
#include <windows.h>
#include <string>
#include <cstring>
#include <initializer_list>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <atomic>
#include "global.h"
#include "tools.h"
#include "db_mgr.h"

#include "GetSelfProfile.h"


using json = nlohmann::json;

namespace {

std::mutex g_ProfileContactCacheMutex;
std::unordered_map<std::string, json> g_ProfileContactCache;

// Set to true only after a full Contact-table enumeration has been merged
// into the cache from WeChat's own SQLite worker thread.  Reset on logout so
// a new account re-runs the backfill.
std::atomic<bool> g_ContactBackfillDone{false};
std::atomic<bool> g_ContactBackfillRunning{false};

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
    std::string alias;
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

std::string ReadContactString(const json& row,
                              std::initializer_list<const char*> names)
{
    for (const char* name : names) {
        if (!name || !row.contains(name) || row[name].is_null())
            continue;
        if (row[name].is_string())
            return row[name].get<std::string>();
        if (row[name].is_number_integer())
            return std::to_string(row[name].get<long long>());
    }
    return {};
}

int ReadContactInteger(const json& row,
                       std::initializer_list<const char*> names)
{
    for (const char* name : names) {
        if (!name || !row.contains(name) || row[name].is_null())
            continue;
        try {
            if (row[name].is_number_integer())
                return row[name].get<int>();
            if (row[name].is_string() && !row[name].get<std::string>().empty())
                return std::stoi(row[name].get<std::string>());
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

void CacheContactRow(const std::string& wxid, const json& row)
{
    if (wxid.empty() || !row.is_object())
        return;
    std::lock_guard<std::mutex> lock(g_ProfileContactCacheMutex);
    // A normal account can have several thousand contacts. Keep the cache
    // bounded, but large enough to hold one complete sync snapshot. The
    // cache is still only our copied JSON data; it never owns WeChat objects.
    if (g_ProfileContactCache.size() >= 4096 &&
        g_ProfileContactCache.find(wxid) == g_ProfileContactCache.end()) {
        g_ProfileContactCache.erase(g_ProfileContactCache.begin());
    }
    g_ProfileContactCache[wxid] = row;
}

bool GetCachedContactRow(const std::string& wxid, json& row)
{
    std::lock_guard<std::mutex> lock(g_ProfileContactCacheMutex);
    const auto it = g_ProfileContactCache.find(wxid);
    if (it == g_ProfileContactCache.end())
        return false;
    row = it->second;
    return true;
}

void ClearContactCache()
{
    std::lock_guard<std::mutex> lock(g_ProfileContactCacheMutex);
    g_ProfileContactCache.clear();
    // The next login must rebuild a complete snapshot for its own account.
    g_ContactBackfillDone.store(false, std::memory_order_release);
}

bool BuildCachedContactSnapshot(std::string& resultJson, size_t offset, size_t limit,
                                size_t& total)
{
    resultJson.clear();
    total = 0;
    if (limit == 0)
        return false;

    std::vector<std::pair<std::string, json>> rows;
    {
        std::lock_guard<std::mutex> lock(g_ProfileContactCacheMutex);
        total = g_ProfileContactCache.size();
        rows.reserve(total);
        for (const auto& entry : g_ProfileContactCache)
            rows.emplace_back(entry.first, entry.second);
    }

    std::sort(rows.begin(), rows.end(),
              [](const auto& left, const auto& right) {
                  return left.first < right.first;
              });

    json contacts = json::array();
    if (offset < rows.size()) {
        const size_t end = (std::min)(rows.size(), offset + limit);
        for (size_t i = offset; i < end; ++i) {
            json row = rows[i].second;
            if (!row.is_object())
                continue;
            if (!row.contains("wxid"))
                row["wxid"] = rows[i].first;
            if (!row.contains("username"))
                row["username"] = rows[i].first;
            // Do not let a cached image blob make a snapshot response
            // unbounded. The URL fields remain available.
            if (row.contains("ImgBuf") && row["ImgBuf"].is_string() &&
                row["ImgBuf"].get<std::string>().size() > 16384) {
                row["ImgBuf"] = "";
                row["ImgBufTruncated"] = true;
            }
            contacts.push_back(std::move(row));
        }
    }

    json response = {
        {"status", 0},
        {"contacts", std::move(contacts)},
        {"offset", offset},
        {"limit", limit},
        {"count", total},
        // The snapshot is authoritative once a full Contact-table
        // enumeration has been merged from WeChat's SQLite worker thread.
        {"complete", g_ContactBackfillDone.load(std::memory_order_acquire)},
        {"source", "wechat-contact-response-cache"}
    };
    resultJson = response.dump();
    return true;
}

// Enumerate the full Contact table on WeChat's own SQLite worker thread and
// merge every row into the bounded contact cache.  This is the sanctioned,
// crash-safe path: RunSqlQueryOnSqliteThread only queues the read-only SELECT
// and lets WeChat's SQLite thread execute it; the HTTP worker never touches
// the internal connection.  Returns the number of rows merged.  When WeChat
// is idle the SQLite thread may not claim the query before the timeout, in
// which case this returns 0 and a later /GetContacts request retries.
size_t BackfillContactsFromDatabase(uint32_t timeoutMs)
{
    if (g_ContactBackfillDone.load(std::memory_order_acquire))
        return 0;
    // Only one backfill may be in flight at a time.  RunSqlQueryOnSqliteThread
    // already rejects concurrent queries, so skip quietly if one is running.
    bool expected = false;
    if (!g_ContactBackfillRunning.compare_exchange_strong(expected, true))
        return 0;
    struct RunningGuard {
        ~RunningGuard() {
            g_ContactBackfillRunning.store(false, std::memory_order_release);
        }
    } runningGuard;

    std::string resultJson;
    if (!RunSqlQueryOnSqliteThread("MicroMsg.db", "SELECT * FROM Contact",
                                   resultJson, timeoutMs))
        return 0;

    size_t merged = 0;
    try {
        const json result = json::parse(resultJson);
        if (result.value("status", -1) != 0 ||
            !result.contains("data") || !result["data"].is_array())
            return 0;
        for (const auto& row : result["data"]) {
            if (!row.is_object())
                continue;
            const std::string wxid = ReadContactString(
                row, {"username", "UserName", "user_name", "wxid", "Wxid"});
            if (wxid.empty())
                continue;
            // The DB row carries the complete profile (nick/alias/avatar).
            // Overwrite any partial session-only entry captured at login.
            CacheContactRow(wxid, row);
            ++merged;
        }
    } catch (...) {
        return 0;
    }

    // A complete Contact enumeration succeeded; the snapshot is now complete.
    g_ContactBackfillDone.store(true, std::memory_order_release);
    return merged;
}

void ApplyContactRow(RuntimeProfile& profile, const json& row)
{
    if (!row.is_object())
        return;
    profile.alias = ReadContactString(row, {"Alias", "alias"});
    profile.area = ReadContactString(row, {"Province", "province"});
    const std::string city = ReadContactString(row, {"City", "city"});
    if (!city.empty()) {
        if (!profile.area.empty())
            profile.area += " ";
        profile.area += city;
    }
    profile.signature = ReadContactString(row, {"Signature", "signature"});
    profile.avatar = ReadContactString(row, {"BigHeadImgUrl", "big_head_url"});
    profile.smallAvatar = ReadContactString(
        row, {"SmallHeadImgUrl", "small_head_url"});
    profile.sex = ReadContactInteger(row, {"Sex", "sex"});
}

void ReadDatabaseProfile(RuntimeProfile& profile)
{
    if (profile.accountId.empty() || !g_IsLogin)
        return;

    // A successful /GetContact request populates this cache.  Reusing it here
    // avoids a second SQLite round trip while WeChat is idle.
    json cachedRow;
    if (GetCachedContactRow(profile.accountId, cachedRow)) {
        ApplyContactRow(profile, cachedRow);
        return;
    }

    // The Contact database is owned by a WeChat worker thread.  The helper
    // queues this read and executes it from the SQLite hook on that thread;
    // the HTTP worker never calls sqlite3_prepare/step on the internal handle.
    std::string resultJson;
    // Optional fields must not make the profile endpoint block for the full
    // contact-query timeout when WeChat is idle and no SQLite callback is
    // currently running.  The required runtime fields are already available.
    if (!RunContactQueryOnSqliteThread(profile.accountId, resultJson, 1000))
        return;

    try {
        const json result = json::parse(resultJson);
        if (result.value("status", -1) != 0 ||
            !result.contains("data") || !result["data"].is_array() ||
            result["data"].empty() || !result["data"][0].is_object()) {
            return;
        }

        const json& row = result["data"][0];
        CacheContactRow(profile.accountId, row);
        ApplyContactRow(profile, row);
    } catch (...) {
        // Optional fields must never make the required runtime fields fail.
    }
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

void RecordCapturedContactRow(const std::string& wxid, const std::string& rowJson)
{
    if (wxid.empty() || rowJson.empty())
        return;
    try {
        const json row = json::parse(rowJson);
        CacheContactRow(wxid, row);
    } catch (...) {
        // A malformed row must never affect the SQLite hook thread.
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
            ClearContactCache();
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
            SelfInfo.alias = runtime.alias.empty() ? runtime.accountId : runtime.alias;
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

            // Serve a row captured by the SQLite hook without touching the
            // internal connection again. This keeps the endpoint usable while
            // WeChat is idle after a contact was recently displayed.
            json cachedRow;
            if (GetCachedContactRow(wxid, cachedRow)) {
                resp = cachedRow;
                resp["status"] = 0;
                resp["contact_found"] = true;
                resp["wxid"] = wxid;
                res.set_content(resp.dump(4, ' ', false), "application/json; charset=utf-8");
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
            CacheContactRow(wxid, resp);
            res.set_content(resp.dump(4, ' ', false), "application/json; charset=utf-8");
        });
}

void RegisterGetContacts(httplib::Server& svr)
{
    auto handler = [](const httplib::Request& req, httplib::Response& res)
    {
        json response;
        if (!g_IsLogin) {
            response["status"] = -401;
            response["msg"] = "wechat is not logged in";
            response["contacts"] = json::array();
            response["count"] = 0;
            res.set_content(response.dump(4, ' ', false),
                            "application/json; charset=utf-8");
            return;
        }

        size_t offset = 0;
        size_t limit = 4096;
        try {
            const json body = req.body.empty() ? json::object() : json::parse(req.body);
            if (body.contains("offset") && body["offset"].is_number_unsigned())
                offset = body["offset"].get<size_t>();
            if (body.contains("limit") && body["limit"].is_number_unsigned())
                limit = body["limit"].get<size_t>();
        } catch (...) {
            response["status"] = -400;
            response["msg"] = "invalid json";
            res.set_content(response.dump(4, ' ', false),
                            "application/json; charset=utf-8");
            return;
        }
        limit = (std::min)(limit, static_cast<size_t>(4096));
        if (limit == 0)
            limit = 1;

        // Complete the snapshot the first time it is requested by enumerating
        // the full Contact table on WeChat's own SQLite thread.  If WeChat is
        // idle and the thread does not claim the query in time, the snapshot
        // stays partial (complete=false) and a later request retries.
        BackfillContactsFromDatabase(15000);

        std::string snapshot;
        size_t total = 0;
        if (!BuildCachedContactSnapshot(snapshot, offset, limit, total)) {
            response["status"] = -500;
            response["msg"] = "contact snapshot unavailable";
            res.set_content(response.dump(4, ' ', false),
                            "application/json; charset=utf-8");
            return;
        }
        res.set_content(snapshot, "application/json; charset=utf-8");
    };

    svr.Get("/GetContacts", handler);
    svr.Post("/GetContacts", handler);
}
