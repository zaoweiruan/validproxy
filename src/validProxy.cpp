#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <chrono>
#include <thread>
#include <windows.h>
#include <sqlite3.h>
#include <curl/curl.h>
#include <boost/json.hpp>

#pragma comment(lib, "sqlite3.lib")
#pragma comment(lib, "libcurl.lib")

namespace json = boost::json;

struct ProxyItem {
    int configType;   // 3=SS, 4=VMess, 5=VLESS, 6=Trojan
    std::string address;
    int port;

    std::string id;       // uuid 或 password
    std::string security; // method / cipher
    std::string flow;     // 新增 (VLESS Vision)

    std::string network;
    std::string streamSecurity;

    std::string remarks;
    std::string indexId;

    // 通用
    std::string requestHost;
    std::string path;
    std::string allowInsecure;
    std::string sni;
    std::string alpn;

    // TLS/Reality
    std::string fingerprint;
    std::string publicKey;
    std::string shortId;
    std::string spiderX;

    // TCP header
    std::string tcpHeaderType; // none/http

    // gRPC
    int grpcMultiMode = 0;

    // KCP
    int kcpMtu = 1350;
    int kcpTti = 20;
    int kcpUplink = 5;
    int kcpDownlink = 20;
    int kcpCongestion = 0;
    std::string kcpHeaderType = "none";

    int muxEnabled;
    int lineNo;
};
struct AppConfig {
    std::string dbPath;
    std::string proxy_query;

};

struct TestResult {
    std::string remarks;
    std::string address;
    int port;
    std::string protocol;
    std::string network;
    std::string security;
    std::string indexId;
    long latency;      // -1 表示失败
    std::string jsonConfig; // 可选：保存生成的 JSON 配置字符串
};

class ResultWriter
{
public:
    ResultWriter(const std::string& dbPath)
    {
        if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK)
            throw std::runtime_error("无法打开数据库");

        const char* sql =
            "INSERT INTO ProfileExItem "
            "(IndexId, Delay, Speed, Sort, Message) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(IndexId) DO UPDATE SET "
            "Delay=excluded.Delay, "
            "Speed=excluded.Speed, "
            "Sort=excluded.Sort, "
            "Message=excluded.Message;";

        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
            throw std::runtime_error("Prepare 写入语句失败");
    }

    void insert(const std::string& indexId,
                long latency,
                int sortOrder)
    {
        sqlite3_reset(stmt);

        sqlite3_bind_text(stmt, 1,
                          indexId.c_str(),
                          -1, SQLITE_TRANSIENT);

        sqlite3_bind_int(stmt, 2, latency);

        sqlite3_bind_double(stmt, 3, 0.0); // Speed 暂时为 0

        sqlite3_bind_int(stmt, 4, sortOrder);

        std::string msg =
            (latency > 0) ? "OK" : "Connection Failed";

        sqlite3_bind_text(stmt, 5,
                          msg.c_str(),
                          -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) != SQLITE_DONE)
        {
            std::cerr << "写入失败: "
                      << sqlite3_errmsg(db)
                      << std::endl;
        }
    }

    ~ResultWriter()
    {
        if (stmt) sqlite3_finalize(stmt);
        if (db) sqlite3_close(db);
    }

private:
    sqlite3* db = nullptr;
    sqlite3_stmt* stmt = nullptr;
};

bool isValidNetwork(const std::string& network)
{
    static const std::set<std::string> valid = {
        "tcp","ws","grpc","h2","httpupgrade","kcp","xhttp"
    };
    return valid.count(network) > 0;
}

json::object buildStream(const ProxyItem& p)
{
    json::object stream;

    // ========= NETWORK =========
    stream["network"] = p.network;

    // ========= SECURITY =========

    if (p.streamSecurity == "tls")
    {
        stream["security"] = "tls";

        json::object tls{
            {"serverName", p.sni.empty() ? p.address : p.sni},
            {"allowInsecure", p.allowInsecure == "true"}
        };

        if (!p.alpn.empty())
            tls["alpn"] = json::array({ p.alpn });

        stream["tlsSettings"] = tls;
    }
    else if (p.streamSecurity == "reality")
    {
        // 仅允许 VLESS / Trojan
        if (p.configType != 5 && p.configType != 6)
            throw std::runtime_error("Reality 仅支持 VLESS 或 Trojan");

        stream["security"] = "reality";

        json::object reality{
            {"serverName", p.sni},
            {"publicKey", p.publicKey},
            {"shortId", p.shortId},
            {"fingerprint", p.fingerprint}
        };

        // spiderX 必须存在时才写
        if (!p.spiderX.empty())
            reality["spiderX"] = p.spiderX;

        // Reality 推荐显式写 show=false（可选但建议）
        reality["show"] = false;

        stream["realitySettings"] = reality;

        // 🚫 删除 flow 自动注入
        // Trojan 不需要 flow
        // VLESS 如需要 flow 应在 outbound 层写，而不是 stream 层
    }
    else
    {
        stream["security"] = "none";
    }

    // ========= TRANSPORT =========

    if (p.network == "tcp")
    {
        if (p.tcpHeaderType == "http")
        {
            stream["tcpSettings"] = {
                {"header", {
                    {"type", "http"},
                    {"request", {
                        {"path", json::array({ p.path.empty() ? "/" : p.path })},
                        {"headers", {
                            {"Host", json::array({ p.requestHost })}
                        }}
                    }}
                }}
            };
        }
    }
    else if (p.network == "ws")
    {
    	json::object ws;
    	ws["path"] = p.path.empty() ? "/" : p.path;

        if (!p.requestHost.empty())
        {
            json::object headers;
            headers["Host"] = p.requestHost;
            ws["headers"] = headers;
        }

        stream["wsSettings"] = ws;
    }
    else if (p.network == "grpc")
    {
        json::object grpc;

        // ✅ 如果链接没有 serviceName，必须生成空字符串
        grpc["serviceName"] = p.path;   // 不要默认填 "grpc"

        grpc["multiMode"] = (p.grpcMultiMode == 1);

        stream["grpcSettings"] = grpc;
    }
    else if (p.network == "h2")
    {
        if (p.streamSecurity != "tls")
            throw std::runtime_error("h2 必须 TLS");

        stream["httpSettings"] = {
            {"path", p.path.empty() ? "/" : p.path},
            {"host", json::array({ p.requestHost })}
        };
    }
    else if (p.network == "kcp")
    {
        stream["kcpSettings"] = {
            {"mtu", p.kcpMtu},
            {"tti", p.kcpTti},
            {"uplinkCapacity", p.kcpUplink},
            {"downlinkCapacity", p.kcpDownlink},
            {"congestion", p.kcpCongestion == 1},
            {"header", { {"type", p.kcpHeaderType} }}
        };
    }

    return stream;
}

json::object buildStream1(const ProxyItem& p)
{
    json::object stream;
    stream["network"] = p.network;

    /* ========== SECURITY ========== */


    if (p.streamSecurity == "tls")
    {
        stream["security"] = "tls";

        json::object tls{
            {"serverName", p.sni.empty() ? p.address : p.sni},
            {"allowInsecure", p.allowInsecure == "true"}
        };

        if (!p.alpn.empty())
            tls["alpn"] = json::array({ p.alpn });

        stream["tlsSettings"] = tls;
    }
    else if (p.streamSecurity == "reality")
    {
        if (p.configType != 5 && p.configType != 6 )
        {
        	throw std::runtime_error("Reality 仅支持 VLESS 或 Trojan");
        }

        stream["network"] = p.network;

        if (p.flow.empty())
        	stream["flow"] = "xtls-rprx-vision";

        stream["security"] = "reality";

        json::object reality{
            {"serverName", p.sni},
            {"publicKey", p.publicKey},
            {"shortId", p.shortId},
            {"fingerprint", p.fingerprint}
        };

        if (!p.spiderX.empty())
            reality["spiderX"] = p.spiderX;

        stream["realitySettings"] = reality;
    }
    else
    {
        stream["security"] = "none";
    }

    /* ========== NETWORK ========== */

    if (p.network == "tcp")
    {
        if (p.tcpHeaderType == "http")
        {
            stream["tcpSettings"] = {
                {"header", {
                    {"type", "http"},
                    {"request", {
                        {"path", json::array({ p.path.empty() ? "/" : p.path })},
                        {"headers", {
                            {"Host", json::array({ p.requestHost })}
                        }}
                    }}
                }}
            };
        }
    }
    else if (p.network == "ws")
    {
        json::object ws{
            {"path", p.path.empty() ? "/" : p.path}
        };

        if (!p.requestHost.empty())
            ws["headers"] = { {"Host", p.requestHost} };

        stream["wsSettings"] = ws;
    }
    else if (p.network == "grpc")
    {
        json::object grpc{
            {"serviceName", p.path.empty() ? "grpc" : p.path},
            {"multiMode", p.grpcMultiMode == 1}
        };

        stream["grpcSettings"] = grpc;
    }
    else if (p.network == "h2")
    {
        if (p.streamSecurity != "tls")
            throw std::runtime_error("h2 必须 TLS");

        stream["httpSettings"] = {
            {"path", p.path.empty() ? "/" : p.path},
            {"host", json::array({ p.requestHost })}
        };
    }
    else if (p.network == "kcp")
    {
        stream["kcpSettings"] = {
            {"mtu", p.kcpMtu},
            {"tti", p.kcpTti},
            {"uplinkCapacity", p.kcpUplink},
            {"downlinkCapacity", p.kcpDownlink},
            {"congestion", p.kcpCongestion == 1},
            {"header", { {"type", p.kcpHeaderType} }}
        };
    }

    return stream;
}

json::object buildOutboundSettings(const ProxyItem& p)
{
    json::object settings;

    switch (p.configType)
    {
    case 1: // VMess
        settings["vnext"] = json::array({
            {
                {"address", p.address},
                {"port", p.port},
                {"users", json::array({
                    {
                        {"id", p.id},
                        {"alterId", 0},
                        {"security", p.security.empty() ? "auto" : p.security}
                    }
                })}
            }
        });
        break;

    case 3: // Shadowsocks
        settings["servers"] = json::array({
            {
                {"address", p.address},
                {"port", p.port},
                {"method", p.security},
                {"password", p.id}
            }
        });
        break;



    case 5: // VLESS
    {
        json::object user{
            {"id", p.id},
            {"encryption", "none"}
        };

        if (!p.flow.empty())
            user["flow"] = p.flow;

        settings["vnext"] = json::array({
            {
                {"address", p.address},
                {"port", p.port},
                {"users", json::array({ user })}
            }
        });
        break;
    }

    case 6: // Trojan
        settings["servers"] = json::array({
            {
                {"address", p.address},
                {"port", p.port},
                {"password", p.id}
            }
        });
        break;

    default:
        throw std::runtime_error("不支持协议类型");
    }

    return settings;
}

std::string generateConfig(const ProxyItem& p)
{
    json::object config;

    config["log"] = {
        {"loglevel", "warning"}
    };

    config["inbounds"] = json::array({
        {
            {"listen","127.0.0.1"},
            {"port",1080},
            {"protocol","socks"},
            {"settings", {{"udp",true}}}
        }
    });

    json::object outbound;

    if (p.configType == 3) outbound["protocol"] = "shadowsocks";
    else if (p.configType == 1) outbound["protocol"] = "vmess";
    else if (p.configType == 5) outbound["protocol"] = "vless";
    else if (p.configType == 6) outbound["protocol"] = "trojan";

    outbound["settings"] = buildOutboundSettings(p);
    outbound["streamSettings"] = buildStream(p);

    if (p.muxEnabled)
        outbound["mux"] = { {"enabled",true}, {"concurrency",8} };

    config["outbounds"] = json::array({ outbound });

    config["routing"] = {
        {"domainStrategy", "IPIfNonMatch"}
    };

    std::ofstream file("temp_config.json");
    file << json::serialize(config);
    file.close();
    std::cout << json::serialize(config) << std::endl;
    return "temp_config.json";
}

void saveResultsCSV(const std::vector<TestResult>& results,
                    const std::string& filename)
{
    std::ofstream file(filename, std::ios::out | std::ios::trunc);

    file << "Remarks,Address,Port,Protocol,Network,Security,Latency(ms),Status\n";

    for (const auto& r : results)
    {
        file << r.remarks << ","
             << r.address << ","
             << r.port << ","
             << r.protocol << ","
             << r.network << ","
             << r.security << ","
			 <<r.jsonConfig<<",";

        if (r.latency > 0)
            file << r.latency << ",OK\n";
        else
            file << "0,FAILED\n";
    }

    file.close();
}

void saveResultsJSON(const std::vector<TestResult>& results,
                     const std::string& filename)
{
    namespace json = boost::json;

    json::array arr;

    for (const auto& r : results)
    {
        json::object obj;
        obj["remarks"] = r.remarks;
        obj["address"] = r.address;
        obj["port"] = r.port;
        obj["protocol"] = r.protocol;
        obj["network"] = r.network;
        obj["security"] = r.security;
        obj["latency"] = r.latency;
        obj["status"] = r.latency > 0 ? "OK" : "FAILED";
        obj["jsonConfig"] = r.jsonConfig;

        arr.push_back(obj);
    }

    std::ofstream file(filename, std::ios::out | std::ios::trunc);
    file << json::serialize(arr);
    file.close();
}

AppConfig loadAppConfig(const std::string& filename)
{

    std::ifstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error("无法打开 config.json");

    std::stringstream buffer;
    buffer << file.rdbuf();

    boost::json::value json =
        boost::json::parse(buffer.str());

    AppConfig cfg;
    cfg.dbPath =
        json.at("database")
            .at("path")
            .as_string()
            .c_str();

    cfg.proxy_query =
        json.at("proxy_query")
            .as_string()
            .c_str();

    return cfg;
}
std::vector<ProxyItem> loadProxiesFromConfig(const AppConfig& cfg)
{
    std::vector<ProxyItem> list;
    sqlite3* db = nullptr;

    try
    {
        /* ---------- 打开数据库 ---------- */

        int rc = sqlite3_open(cfg.dbPath.c_str(), &db);
        if (rc != SQLITE_OK)
        {
            std::string err =
                db ? sqlite3_errmsg(db) : "未知错误";

            throw std::runtime_error(
                "无法打开数据库: " + cfg.dbPath +
                " 错误: " + err);
        }



        /* ---------- 查询代理 ---------- */

        const char* query =cfg.proxy_query.c_str();
        std::cout<<"sql "<<query<<std::endl;

        sqlite3_stmt* stmt = nullptr;

        rc = sqlite3_prepare_v2(db, query, -1, &stmt, nullptr);
        if (rc != SQLITE_OK)
        {
            throw std::runtime_error(
                "SQL prepare 失败: " +
                std::string(sqlite3_errmsg(db)));
        }

        /* ---------- 读取数据 ---------- */

        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
        {
            ProxyItem p{};

            auto getText = [&](int col) -> std::string {
                const unsigned char* text =
                    sqlite3_column_text(stmt, col);
                return text ? reinterpret_cast<const char*>(text) : "";
            };

            p.configType = sqlite3_column_int(stmt, 0);
            p.address = getText(1);
            p.port = sqlite3_column_int(stmt, 2);
            p.id = getText(3);
            p.security = getText(4);
            p.network = getText(5);
            p.streamSecurity = getText(6);
            p.remarks = getText(7);
            p.requestHost = getText(8);
            p.path = getText(9);
            p.allowInsecure = getText(10);
            p.sni = getText(11);
            p.alpn = getText(12);
            p.fingerprint = getText(13);
            p.publicKey = getText(14);
            p.shortId = getText(15);
            p.spiderX = getText(16);
            p.muxEnabled = sqlite3_column_int(stmt, 17);
            p.indexId = getText(18);
            p.lineNo=sqlite3_column_int(stmt, 19);
            p.flow = getText(20);
            list.push_back(std::move(p));
        }

        if (rc != SQLITE_DONE)
        {
            throw std::runtime_error(
                "SQL step 执行异常: " +
                std::string(sqlite3_errmsg(db)));
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        std::cout << "成功加载代理数量: "
                  << list.size() << std::endl;

        return list;
    }
    catch (...)
    {
        if (db)
            sqlite3_close(db);

        throw;  // 继续向上抛出
    }
}

void writeResultsToDB(const std::string& dbPath,
                      const std::vector<TestResult>& results)
{
    sqlite3* db = nullptr;

    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK)
        throw std::runtime_error("无法打开数据库写入结果");

    char* errMsg = nullptr;

    /* 开启事务，提高性能 */
    sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    const char* sql =
        "INSERT INTO ProfileExItem "
        "(IndexId, Delay, Speed, Sort, Message) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(IndexId) DO UPDATE SET "
        "Delay=excluded.Delay, "
        "Speed=excluded.Speed, "
        "Sort=excluded.Sort, "
        "Message=excluded.Message;";

    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        sqlite3_close(db);
        throw std::runtime_error("Prepare 写入语句失败");
    }

    int sortOrder = 1;

    for (const auto& r : results)
    {
        sqlite3_reset(stmt);

        sqlite3_bind_text(stmt, 1,
                          r.indexId.c_str(),
                          -1, SQLITE_TRANSIENT);

        sqlite3_bind_int(stmt, 2, r.latency);

        /* Speed 暂时设为 0 */
        sqlite3_bind_double(stmt, 3, 0.0);

        sqlite3_bind_int(stmt, 4, sortOrder++);

        std::string msg =
            (r.latency > 0)
            ? "OK"
            : "Connection Failed";

        sqlite3_bind_text(stmt, 5,
                          msg.c_str(),
                          -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) != SQLITE_DONE)
        {
            std::cerr << "写入失败: "
                      << sqlite3_errmsg(db)
                      << std::endl;
        }
    }

    sqlite3_finalize(stmt);

    sqlite3_exec(db, "COMMIT;", nullptr, nullptr, &errMsg);

    sqlite3_close(db);

    std::cout << "测速结果已写入 ProfileExItem\n";
}


PROCESS_INFORMATION startXray(const std::string& config)
{
    PROCESS_INFORMATION pi{};
    STARTUPINFOA si{};
    si.cb = sizeof(si);

    std::string cmd = "xray.exe -config " + config;

    CreateProcessA(
        NULL,
        cmd.data(),
        NULL, NULL, FALSE,
        CREATE_NO_WINDOW,
        NULL, NULL,
        &si, &pi);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    return pi;
}

long testLatency()
{
    CURL* curl = curl_easy_init();
    if (!curl)
        return -1;

    curl_easy_setopt(curl, CURLOPT_URL,
                     "https://www.gstatic.com/generate_204");

    curl_easy_setopt(curl, CURLOPT_PROXY,
                     "http://127.0.0.1:1080");

    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 8L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                     +[](char*, size_t s, size_t n, void*) {
                         return s * n;
                     });

    CURLcode res = curl_easy_perform(curl);

//    if (res != CURLE_OK)
//    {
//        curl_easy_cleanup(curl);
//        return -1;
//    }
    long httpCode = 0;
    curl_easy_getinfo(curl,
                      CURLINFO_RESPONSE_CODE,
                      &httpCode);

    if (httpCode != 204)
        return -1;
//    double totalTime = 0.0;
//    curl_easy_getinfo(curl,
//                      CURLINFO_TOTAL_TIME,
//                      &totalTime);
    double startTransfer = 0;
    curl_easy_getinfo(curl,
                      CURLINFO_STARTTRANSFER_TIME,
                      &startTransfer);
    curl_easy_cleanup(curl);

    // 秒转毫秒
//    return static_cast<long>(totalTime * 1000);
    return static_cast<long>(startTransfer * 100);
}

int main()
{
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);
    curl_global_init(CURL_GLOBAL_ALL);
    try
    {
        AppConfig cfg = loadAppConfig("config.json");

        std::cout << "数据库路径: "
                  << cfg.dbPath << std::endl;

        auto proxies = loadProxiesFromConfig(cfg);
        std::cout << "--------------------------------\n";

        std::cout << "获取代理数量: " << proxies.size() << "\n";
        std::cout << "--------------------------------\n";

    std::vector<TestResult> results;

    ResultWriter writer(cfg.dbPath);
    int sortOrder = 1;

    for (auto& p : proxies)
    {
         TestResult result;
        if (p.configType == 3) result.protocol = "Shadowsocks";
        if (p.configType == 5) result.protocol = "VLESS";
        if (p.configType == 6) result.protocol = "Trojan";
        if (p.configType == 1) result.protocol = "VMESS";

        std::cout << "测试: " << p.lineNo<<"\t"<<p.remarks<<"\t"<<p.address <<"\t"<<result.protocol << std::endl;

			try {
				auto config = generateConfig(p);

				auto pi = startXray(config);

				long latency = testLatency();

				result.remarks = p.remarks;
				result.address = p.address;
				result.port = p.port;
				result.network = p.network;
				result.security = p.streamSecurity;

				result.indexId = p.indexId;
				result.latency = latency > 0 ? latency : -1;
				result.jsonConfig = json::serialize(config);
				writer.insert(p.indexId, latency, sortOrder++);

				results.push_back(result);

				if (latency > 0)
					std::cout << "成功 " << latency << " ms\n";
				else
					std::cout << "失败\n";

				TerminateProcess(pi.hProcess, 0);
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);

				std::cout << "----------------------\n";
			}
			catch (const std::exception &e) {
				std::cerr << "配置错误: " << e.what() << "\n";
				result.latency = -1;
				results.push_back(result);
				continue;
			}

    }

    /* 保存结果 */
    //writeResultsToDB(cfg.dbPath, results);
//    saveResultsCSV(results, "test_result.csv");
    saveResultsJSON(results, "test_result.json");
    // 后续测速逻辑...
}
catch (const std::exception& e)
{
    std::cerr << e.what() << std::endl;
}

    curl_global_cleanup();

    std::cout << "测速结果已保存\n";

    return 0;
}
