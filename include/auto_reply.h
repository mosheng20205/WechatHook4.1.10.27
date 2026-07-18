#pragma once
#include <string>
#include <vector>

// Full auto-reply rules engine with JSON persistence for WeChat 4.1.10.27.
// The config lives next to the WeChat host executable (same directory as
// wx.ini) in autoreply.json.  All accessors are thread-safe; the receive Hook
// only calls BuildReply, never touches disk on its own thread.
namespace AutoReply
{
    enum class MatchType
    {
        Contains = 0,
        Equals = 1,
        Prefix = 2,
        Suffix = 3,
        Regex = 4
    };

    enum class Scope
    {
        All = 0,
        Friend = 1,
        Group = 2
    };

    struct Rule
    {
        std::string keyword;
        MatchType match = MatchType::Contains;
        std::string reply_template;   // supports {content} {sender} {room}
        Scope scope = Scope::All;
        bool enabled = true;
    };

    struct Config
    {
        bool enabled = false;         // global master switch (default off)
        bool friend_enabled = true;   // reply to single-friend messages
        bool group_enabled = false;   // reply to @chatroom messages
        std::string default_template = "[auto-reply] {content}";
        std::vector<Rule> rules;
        std::vector<std::string> whitelist; // if non-empty, only these reply
        std::vector<std::string> blacklist; // never reply to these senders
    };

    // Load config from autoreply.json next to the host executable.  Missing or
    // malformed files fall back to safe defaults (global switch off).
    void LoadFromDisk();
    // Persist the current config.  Returns true on success.
    bool SaveToDisk();

    // Thread-safe snapshot access.
    Config GetConfig();
    void SetConfig(const Config& cfg);

    // Serialize the current config to a JSON string for HTTP responses.
    std::string ToJsonString();
    // Merge the fields present in jsonText onto the current config, then save.
    // Fields that are absent keep their current value (backward compatible with
    // posting only {"group_enabled":true}).  Returns false and fills errorOut
    // on parse errors.
    bool MergeFromJsonString(const std::string& jsonText, std::string& errorOut);

    // Rules-only JSON helpers for /AutoReply/rules.
    std::string RulesToJsonString();
    bool AddRuleFromJson(const std::string& jsonText, std::string& errorOut);
    bool DeleteRuleAt(size_t index);
    void ClearRules();
    bool ReplaceRulesFromJson(const std::string& jsonText, std::string& errorOut);

    // Decide the reply for one incoming message.  Returns true and fills
    // replyOut when a reply should be sent.  Applies the global switch, the
    // friend/group switch, black/white lists, rule matching and template
    // rendering.  content/sender/room feed {content} {sender} {room}.
    bool BuildReply(bool isGroup, const std::string& sender, const std::string& room,
                    const std::string& content, std::string& replyOut);
}
