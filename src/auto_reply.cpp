#include "auto_reply.h"
#include "json.hpp"
#include "global.h"

#include <windows.h>
#include <shlwapi.h>
#include <mutex>
#include <regex>
#include <fstream>
#include <sstream>

#pragma comment(lib, "Shlwapi.lib")

using json = nlohmann::json;

namespace AutoReply
{
    static std::mutex g_ConfigMutex;
    static Config g_Config;
    static bool g_Loaded = false;

    // ---- helpers -----------------------------------------------------------

    static std::wstring ConfigPath()
    {
        wchar_t exePath[MAX_PATH] = {0};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        PathRemoveFileSpecW(exePath);
        wchar_t full[MAX_PATH] = {0};
        swprintf_s(full, L"%s\\autoreply.json", exePath);
        return std::wstring(full);
    }

    static const char* MatchTypeToString(MatchType m)
    {
        switch (m) {
        case MatchType::Equals: return "equals";
        case MatchType::Prefix: return "prefix";
        case MatchType::Suffix: return "suffix";
        case MatchType::Regex:  return "regex";
        case MatchType::Contains:
        default: return "contains";
        }
    }

    static MatchType MatchTypeFromString(const std::string& s)
    {
        if (s == "equals") return MatchType::Equals;
        if (s == "prefix") return MatchType::Prefix;
        if (s == "suffix") return MatchType::Suffix;
        if (s == "regex")  return MatchType::Regex;
        return MatchType::Contains;
    }

    static const char* ScopeToString(Scope s)
    {
        switch (s) {
        case Scope::Friend: return "friend";
        case Scope::Group:  return "group";
        case Scope::All:
        default: return "all";
        }
    }

    static Scope ScopeFromString(const std::string& s)
    {
        if (s == "friend") return Scope::Friend;
        if (s == "group")  return Scope::Group;
        return Scope::All;
    }

    static json RuleToJson(const Rule& r)
    {
        json j;
        j["keyword"] = r.keyword;
        j["match"] = MatchTypeToString(r.match);
        j["template"] = r.reply_template;
        j["scope"] = ScopeToString(r.scope);
        j["enabled"] = r.enabled;
        return j;
    }

    static Rule RuleFromJson(const json& j)
    {
        Rule r;
        r.keyword = j.value("keyword", std::string());
        r.match = MatchTypeFromString(j.value("match", std::string("contains")));
        r.reply_template = j.value("template", std::string());
        r.scope = ScopeFromString(j.value("scope", std::string("all")));
        r.enabled = j.value("enabled", true);
        return r;
    }

    static json ConfigToJson(const Config& c)
    {
        json j;
        j["enabled"] = c.enabled;
        j["friend_enabled"] = c.friend_enabled;
        j["group_enabled"] = c.group_enabled;
        j["default_template"] = c.default_template;
        j["rules"] = json::array();
        for (const auto& r : c.rules)
            j["rules"].push_back(RuleToJson(r));
        j["whitelist"] = c.whitelist;
        j["blacklist"] = c.blacklist;
        return j;
    }

    // Mirror the group switch into the legacy status counter so /QueryDB/status
    // and older clients keep reporting the same value.
    static void SyncLegacyMirror(bool groupEnabled)
    {
        InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_AutoReplyGroupEnabled),
                              groupEnabled ? 1 : 0);
    }

    static std::string RenderTemplate(const std::string& tmpl, const std::string& content,
                                      const std::string& sender, const std::string& room)
    {
        std::string out;
        out.reserve(tmpl.size() + content.size());
        for (size_t i = 0; i < tmpl.size();) {
            if (tmpl[i] == '{') {
                if (tmpl.compare(i, 9, "{content}") == 0) { out += content; i += 9; continue; }
                if (tmpl.compare(i, 8, "{sender}") == 0) { out += sender; i += 8; continue; }
                if (tmpl.compare(i, 6, "{room}") == 0) { out += room; i += 6; continue; }
            }
            out += tmpl[i++];
        }
        return out;
    }

    static bool MatchOne(const Rule& r, const std::string& content)
    {
        const std::string& kw = r.keyword;
        switch (r.match) {
        case MatchType::Equals:
            return content == kw;
        case MatchType::Prefix:
            return content.size() >= kw.size() && content.compare(0, kw.size(), kw) == 0;
        case MatchType::Suffix:
            return content.size() >= kw.size() &&
                   content.compare(content.size() - kw.size(), kw.size(), kw) == 0;
        case MatchType::Regex:
            try {
                std::regex re(kw);
                return std::regex_search(content, re);
            } catch (...) {
                return false;
            }
        case MatchType::Contains:
        default:
            return !kw.empty() && content.find(kw) != std::string::npos;
        }
    }

    static bool ScopeMatches(Scope scope, bool isGroup)
    {
        if (scope == Scope::All) return true;
        if (scope == Scope::Group) return isGroup;
        return !isGroup; // Friend
    }

    static bool ListContains(const std::vector<std::string>& list, const std::string& value)
    {
        for (const auto& item : list)
            if (item == value)
                return true;
        return false;
    }

    // ---- public API --------------------------------------------------------

    void LoadFromDisk()
    {
        Config loaded; // defaults
        bool ok = false;
        try {
            std::ifstream in(ConfigPath(), std::ios::binary);
            if (in) {
                std::stringstream ss;
                ss << in.rdbuf();
                const std::string text = ss.str();
                if (!text.empty()) {
                    const json j = json::parse(text);
                    loaded.enabled = j.value("enabled", loaded.enabled);
                    loaded.friend_enabled = j.value("friend_enabled", loaded.friend_enabled);
                    loaded.group_enabled = j.value("group_enabled", loaded.group_enabled);
                    loaded.default_template = j.value("default_template", loaded.default_template);
                    if (j.contains("rules") && j["rules"].is_array()) {
                        loaded.rules.clear();
                        for (const auto& r : j["rules"])
                            loaded.rules.push_back(RuleFromJson(r));
                    }
                    if (j.contains("whitelist") && j["whitelist"].is_array())
                        loaded.whitelist = j["whitelist"].get<std::vector<std::string>>();
                    if (j.contains("blacklist") && j["blacklist"].is_array())
                        loaded.blacklist = j["blacklist"].get<std::vector<std::string>>();
                    ok = true;
                }
            }
        } catch (...) {
            ok = false;
        }

        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        g_Config = ok ? loaded : Config{};
        g_Loaded = true;
        SyncLegacyMirror(g_Config.group_enabled);
    }

    bool SaveToDisk()
    {
        json j;
        {
            std::lock_guard<std::mutex> lock(g_ConfigMutex);
            j = ConfigToJson(g_Config);
        }
        try {
            std::ofstream out(ConfigPath(), std::ios::binary | std::ios::trunc);
            if (!out)
                return false;
            const std::string text = j.dump(2);
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            return out.good();
        } catch (...) {
            return false;
        }
    }

    Config GetConfig()
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        return g_Config;
    }

    void SetConfig(const Config& cfg)
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        g_Config = cfg;
        SyncLegacyMirror(g_Config.group_enabled);
    }

    std::string ToJsonString()
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        return ConfigToJson(g_Config).dump();
    }

    bool MergeFromJsonString(const std::string& jsonText, std::string& errorOut)
    {
        json j;
        try {
            j = json::parse(jsonText.empty() ? "{}" : jsonText);
        } catch (...) {
            errorOut = "invalid json";
            return false;
        }
        if (!j.is_object()) {
            errorOut = "expected a json object";
            return false;
        }

        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        auto readBool = [&](const char* key, bool& target) {
            if (j.contains(key)) {
                if (j[key].is_boolean()) target = j[key].get<bool>();
                else if (j[key].is_number_integer()) target = j[key].get<int>() != 0;
            }
        };
        readBool("enabled", g_Config.enabled);
        readBool("friend_enabled", g_Config.friend_enabled);
        readBool("group_enabled", g_Config.group_enabled);
        if (j.contains("default_template") && j["default_template"].is_string())
            g_Config.default_template = j["default_template"].get<std::string>();
        if (j.contains("rules") && j["rules"].is_array()) {
            g_Config.rules.clear();
            for (const auto& r : j["rules"])
                g_Config.rules.push_back(RuleFromJson(r));
        }
        if (j.contains("whitelist") && j["whitelist"].is_array())
            g_Config.whitelist = j["whitelist"].get<std::vector<std::string>>();
        if (j.contains("blacklist") && j["blacklist"].is_array())
            g_Config.blacklist = j["blacklist"].get<std::vector<std::string>>();
        SyncLegacyMirror(g_Config.group_enabled);
        errorOut.clear();
        return true;
    }

    std::string RulesToJsonString()
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        json arr = json::array();
        for (const auto& r : g_Config.rules)
            arr.push_back(RuleToJson(r));
        return arr.dump();
    }

    bool AddRuleFromJson(const std::string& jsonText, std::string& errorOut)
    {
        json j;
        try {
            j = json::parse(jsonText.empty() ? "{}" : jsonText);
        } catch (...) {
            errorOut = "invalid json";
            return false;
        }
        const json rule = j.contains("rule") ? j["rule"] : j;
        if (!rule.is_object() || !rule.contains("keyword")) {
            errorOut = "rule.keyword is required";
            return false;
        }
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        g_Config.rules.push_back(RuleFromJson(rule));
        errorOut.clear();
        return true;
    }

    bool DeleteRuleAt(size_t index)
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        if (index >= g_Config.rules.size())
            return false;
        g_Config.rules.erase(g_Config.rules.begin() + index);
        return true;
    }

    void ClearRules()
    {
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        g_Config.rules.clear();
    }

    bool ReplaceRulesFromJson(const std::string& jsonText, std::string& errorOut)
    {
        json j;
        try {
            j = json::parse(jsonText.empty() ? "{}" : jsonText);
        } catch (...) {
            errorOut = "invalid json";
            return false;
        }
        const json arr = j.contains("rules") ? j["rules"] : j;
        if (!arr.is_array()) {
            errorOut = "rules array is required";
            return false;
        }
        std::vector<Rule> next;
        for (const auto& r : arr)
            next.push_back(RuleFromJson(r));
        std::lock_guard<std::mutex> lock(g_ConfigMutex);
        g_Config.rules = std::move(next);
        errorOut.clear();
        return true;
    }

    bool BuildReply(bool isGroup, const std::string& sender, const std::string& room,
                    const std::string& content, std::string& replyOut)
    {
        Config cfg = GetConfig();
        if (!cfg.enabled || content.empty())
            return false;
        if (isGroup ? !cfg.group_enabled : !cfg.friend_enabled)
            return false;
        if (!cfg.blacklist.empty() && ListContains(cfg.blacklist, sender))
            return false;
        if (!cfg.whitelist.empty() && !ListContains(cfg.whitelist, sender))
            return false;

        // First matching, enabled, in-scope rule wins.
        for (const auto& r : cfg.rules) {
            if (!r.enabled || !ScopeMatches(r.scope, isGroup))
                continue;
            if (MatchOne(r, content)) {
                replyOut = RenderTemplate(r.reply_template, content, sender, room);
                return !replyOut.empty();
            }
        }

        if (cfg.default_template.empty())
            return false;
        replyOut = RenderTemplate(cfg.default_template, content, sender, room);
        return !replyOut.empty();
    }
}
