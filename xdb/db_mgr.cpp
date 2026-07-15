#include "db_mgr.h"
#include "xwechat_offsets.h"
#include "SundaySearch.h"
#include "global.h"
#include "tools.h"

static void SetDbDebug(const char* text) {
	if (!text) return;
	sprintf_s(g_DbDebugText, sizeof(g_DbDebugText), "%s", text);
}

static void SetDbDebug2(const char* text, size_t value) {
	if (!text) return;
	sprintf_s(g_DbDebugText, sizeof(g_DbDebugText), "%s: 0x%llX", text, static_cast<unsigned long long>(value));
}

static bool SafeReadablePtr(const void* ptr) {
	if (!ptr) return false;
	MEMORY_BASIC_INFORMATION mbi{};
	if (!VirtualQuery(ptr, &mbi, sizeof(mbi)))
		return false;
	if (mbi.State != MEM_COMMIT)
		return false;
	if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
		return false;
	return true;
}

static bool SafeSqliteErrcode(sqlite3_api_routines* routines, LPVOID db, int& rc) {
	if (!routines || !routines->errcode || !SafeReadablePtr(db))
		return false;
	__try {
		rc = routines->errcode(db);
		return true;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}
}

static void codec_get_key(sqlite3CodecGetKey func, sqlite3* db, int index, void** pKey, int* pLen) {
	__try {
		func(db, index, pKey, pLen);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		//这里输出异常调试信息 
	}
}

namespace xmgr {

	static std::string toHexString(const std::string& str)
	{
		static const char hex[] = "0123456789ABCDEF";
		std::string out;
		out.reserve(str.size() * 2);

		for (size_t i = 0; i < str.size(); ++i)
		{
			out.push_back(hex[(unsigned char)str[i] >> 4]);
			out.push_back(hex[(unsigned char)str[i] & 0x0F]);
		}
		return out;
	}

	DatabaseMgr::DatabaseMgr() {
		SetDbDebug("DatabaseMgr ctor begin");
		size_t module_base = (size_t)g_hWeixinDll;
		m_sqlite3Rountines = (sqlite3_api_routines*)(module_base + XWECHAT_SQLITE3_API_ROUTINES_OFFSET);
		m_sqlcipherRountines = (sqlcipher_api_routines*)(module_base + XWECHAT_SQLCIPHER_API_ROUTINES_OFFSET);
		m_codecGetKey = (sqlite3CodecGetKey)(module_base + XWECHAT_SQLITE3_CODEC_GET_KEY_FUNC);
		LPVOID patchAddress = (LPVOID)((size_t)m_sqlite3Rountines->backup_init + 0xAD);
		std::vector<BYTE> nopData(14, 0x90);
		m_backupAsmCode.resize(nopData.size(), 0);
		ReadProcessMemory(GetCurrentProcess(), patchAddress, m_backupAsmCode.data(), m_backupAsmCode.size(), nullptr);
		WriteProcessMemory(GetCurrentProcess(), patchAddress, (LPCVOID)nopData.data(), nopData.size(), 0);
		SetDbDebug("DatabaseMgr ctor ok");
	}

	DatabaseMgr::~DatabaseMgr() {
		if (m_sqlite3Rountines != nullptr && m_backupAsmCode.size() != 0) {
			LPVOID patchAddress = (LPVOID)((size_t)m_sqlite3Rountines->backup_init + 0xAD);
			WriteProcessMemory(GetCurrentProcess(), patchAddress, (LPCVOID)m_backupAsmCode.data(), m_backupAsmCode.size(), 0);
			m_backupAsmCode.resize(0);
		}
	}

	nlohmann::ordered_json DatabaseMgr::execute(sqlite3* db, const std::string& sql)
	{
		nlohmann::ordered_json rdata = { {"status",0},{"desc",""} };
		if (db == nullptr) {
			rdata["status"] = -1;
			rdata["desc"] = "input db handle is nullptr";
			return rdata;
		}
		sqlite3_stmt* stmt = nullptr;
		int rc = m_sqlite3Rountines->prepare((LPVOID)db, sql.c_str(), -1, &stmt, 0);
		if (rc != SQLITE_OK) {
			rdata["status"] = rc;
			rdata["desc"] = format_string("execute %s failed", "sqlite3_prepare");
			return rdata;
		}
		nlohmann::ordered_json items = nlohmann::ordered_json::array();
		while (m_sqlite3Rountines->step(stmt) == SQLITE_ROW)
		{
			int col_count = m_sqlite3Rountines->column_count(stmt);
			nlohmann::ordered_json item;
			for (int i = 0; i < col_count; i++)
			{
				const char* ColName = m_sqlite3Rountines->column_name(stmt, i);
				int nType = m_sqlite3Rountines->column_type(stmt, i);
				const void* pReadBlobData = m_sqlite3Rountines->column_blob(stmt, i);
				int nLength = m_sqlite3Rountines->column_bytes(stmt, i);
				std::string key(ColName);
				std::string value;
				switch (nType)
				{
				case SQLITE_NULL:
				{
					value = "";
					break;
				}
				case SQLITE_BLOB:
				{
					value = pReadBlobData ? toHexString(std::string((char*)pReadBlobData, nLength)) : "";
					break;
				}
				default:
				{
					value = pReadBlobData ? std::string((char*)pReadBlobData, nLength) : "";
					break;
				}
				}
				item[key] = value;
			}
			items.push_back(item);
		}
		m_sqlite3Rountines->finalize(stmt);
		rdata["data"] = items;
		return rdata;
	}

	nlohmann::ordered_json DatabaseMgr::execute(const std::string& dbname, const std::string& sql)
	{
		nlohmann::ordered_json rdata = { {"status",0},{"desc",""} };
		LPVOID dbHandle = getDatabaseHandle(dbname);
		if (dbHandle == nullptr) {
			rdata["status"] = -1;
			rdata["desc"] = format_string("get database handle which named %s failed", dbname);
			return rdata;
		}
		rdata = execute((sqlite3*)dbHandle, sql);
		return rdata;
	}

	std::string DatabaseMgr::codec_get_key(const std::string& dbname) {
		LPVOID dbHandle = getDatabaseHandle(dbname);
		if (dbHandle == nullptr)
			return "";
		return codec_get_key((sqlite3*)dbHandle);
	}

	std::string DatabaseMgr::codec_get_key(sqlite3* db) {
		char* pKey = nullptr;
		int iLen = 0;
		std::string szKey;
		return szKey;
		if (m_codecGetKey == nullptr)
			return szKey;
		nlohmann::ordered_json queryResult = execute(db, std::string("PRAGMA cipher_store_pass"));
		if (queryResult["data"][0]["cipher_store_pass"] == 0) {
			return szKey;
		}
		::codec_get_key(m_codecGetKey, db, 0, (void**)&pKey, &iLen);
		if (pKey == nullptr)
			return szKey;
		szKey = std::string(pKey, iLen);
		return szKey;
	}

	void DatabaseMgr::backup_xprogress(int remaining, int pagecount) {
		//LL_DEBUG("backup process: %d/%d\n", pagecount - remaining, pagecount);
		//OutputDebugStringA("[backup process]\n");
	}

	int DatabaseMgr::backup(sqlite3* db, const std::string& out_path)
	{
		int rc = SQLITE_OK;
		if (db == nullptr) {
			return -1;
		}
		sqlite3* pNewDbHandle = nullptr;
		sqlite3_backup* pBackupHandle = nullptr;
		rc = m_sqlite3Rountines->open(out_path.c_str(), &pNewDbHandle);
		if (rc == SQLITE_OK) {
			pBackupHandle = m_sqlite3Rountines->backup_init(pNewDbHandle, (const char*)"main", db, (const char*)"main");
			if (pBackupHandle) {
				do {
					rc = m_sqlite3Rountines->backup_step(pBackupHandle, 5);
					backup_xprogress(
						m_sqlite3Rountines->backup_remaining(pBackupHandle),
						m_sqlite3Rountines->backup_pagecount(pBackupHandle)
					);
					if (rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED) {
						m_sqlite3Rountines->sleep(50);
					}
				} while (rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED);
				(void)m_sqlite3Rountines->backup_finish(pBackupHandle);
			}
			rc = m_sqlite3Rountines->errcode(pNewDbHandle);
		}
		(void)m_sqlite3Rountines->close(pNewDbHandle);
		return rc;
	}

	int DatabaseMgr::backup(const std::string& dbname, const std::string& out_path)
	{
		int rc = SQLITE_OK;
		sqlite3* pExistDbHandle = (sqlite3*)getDatabaseHandle(dbname);
		if (pExistDbHandle == nullptr) {
			return -1;
		}
		return backup(pExistDbHandle, out_path);
	}

	const std::map<std::string, LPVOID>& DatabaseMgr::searchDatabases() {
		SetDbDebug("searchDatabases begin");
		std::lock_guard<std::mutex> lg(m_searchDbMtx);
		if (!g_IsLogin) {
			SetDbDebug("searchDatabases not login");
			m_dbs.clear();
			return m_dbs;
		}
		SetDbDebug("searchDatabases validate cached");
		for (auto& it : m_dbs) {
			int cachedRc = SQLITE_MISUSE;
			if (!SafeSqliteErrcode(m_sqlite3Rountines, it.second, cachedRc) || cachedRc == SQLITE_MISUSE) {
				m_dbs.clear();
				break;
			}
		}
		if (m_dbs.size() > 0) {
			SetDbDebug("searchDatabases cached ok");
			return m_dbs;
		}
		std::vector<LPVOID> results;
		size_t vfs_addr = (size_t)g_hWeixinDll + XWECHAT_SQLITE3_VFS_OFFSET;
		SetDbDebug2("searchDatabases scan pattern", vfs_addr);
		ScanPattern(GetCurrentProcess(), (BYTE*)&vfs_addr, sizeof(LPVOID), results);
		SetDbDebug2("searchDatabases scan count", results.size());
		for (size_t i = 0; i < results.size(); i++) {
			auto result = results[i];
			SetDbDebug2("searchDatabases candidate", reinterpret_cast<size_t>(result));
			int rc = SQLITE_MISUSE;
			if (SafeSqliteErrcode(m_sqlite3Rountines, result, rc)) {
				SetDbDebug2("searchDatabases errcode", static_cast<size_t>(rc));
				if (rc == SQLITE_OK) {
					try {
						SetDbDebug("searchDatabases pragma begin");
						nlohmann::ordered_json queryResult = execute(result, "PRAGMA database_list");
						SetDbDebug("searchDatabases pragma ok");
						if (!queryResult.contains("data") || !queryResult["data"].is_array() ||
							queryResult["data"].empty() || !queryResult["data"][0].contains("file")) {
							continue;
						}
						std::string dbpath = queryResult["data"][0]["file"].get<std::string>();
						sprintf_s(g_DbDebugText, sizeof(g_DbDebugText), "searchDatabases dbpath: %s", dbpath.c_str());
						if (dbpath.empty())
							continue;
						auto pos = dbpath.find_last_of("\\/");
						std::string dbname = pos == std::string::npos ? dbpath : dbpath.substr(pos + 1);
						if (!dbname.empty())
							m_dbs[dbname] = result;
					}
					catch (...) {
						SetDbDebug("searchDatabases candidate exception");
						continue;
					}
				}
			}
		}
		SetDbDebug2("searchDatabases done count", m_dbs.size());
		return m_dbs;
	}

	LPVOID DatabaseMgr::getDatabaseHandle(const std::string& dbname)
	{
		auto& dbs = searchDatabases();
		if (m_dbs.find(dbname) == m_dbs.end())
			return nullptr;
		return m_dbs[dbname];
	}

	nlohmann::ordered_json DatabaseMgr::getDatabaseInfo() {
		nlohmann::ordered_json jdbs = nlohmann::ordered_json::array();
		if (!g_IsLogin)
			return jdbs;
		// Force a scan. The presence of live MicroMsg databases is the
		// observable login signal available in this build.
		m_dbs.clear();
		auto& dbs = searchDatabases();
		for (auto& db : dbs) {
			nlohmann::json jdb = { {"dbName",db.first},{"dbHandle",(size_t)db.second} };
			
			//std::string debugMsg = "[getDatabaseInfo] dbName " + db.first + "\n";
			//OutputDebugStringA(debugMsg.c_str());

			// jdb["dbKey"] = codec_get_key(db.second);
			jdbs.push_back(jdb);
		}
		return jdbs;
	}
}
