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
    int configType;
    std::string address;
    int port;
    std::string id;
    std::string security;
    std::string network;
    std::string streamSecurity;
    std::string remarks;

    std::string requestHost;
    std::string path;
    std::string allowInsecure;
    std::string sni;
    std::string alpn;
    std::string fingerprint;
    std::string publicKey;
    std::string shortId;
    std::string spiderX;
    std::string indexId;
    int lineNo;
    int muxEnabled;
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
    if (!isValidNetwork(p.network))
        throw std::runtime_error("非法 network: " + p.network);

    json::object stream;
    stream["network"] = p.network;

    /* security */
    if (p.streamSecurity == "tls")
    {
        stream["security"] = "tls";

        json::object tls;
        tls["serverName"] =
            p.sni.empty() ? p.address : p.sni;
        tls["allowInsecure"] =
            (p.allowInsecure == "true");

        if (!p.alpn.empty())
            tls["alpn"] = json::array({ p.alpn });

        stream["tlsSettings"] = tls;
    }
    else if (p.streamSecurity == "reality")
    {
        stream["security"] = "reality";

        json::object reality;
        reality["serverName"] = p.sni;
        reality["publicKey"] = p.publicKey;
        reality["shortId"] = p.shortId;
        reality["fingerprint"] = p.fingerprint;
        reality["spiderX"] = p.spiderX;

        stream["realitySettings"] = reality;
    }
    else
    {
        stream["security"] = "none";
    }

    /* network specific */

    if (p.network == "ws")
    {
        json::object ws;
        ws["path"] = p.path.empty() ? "/" : p.path;

        if (!p.requestHost.empty())
        {
            ws["headers"] = {
                {"Host", p.requestHost}
            };
        }

        stream["wsSettings"] = ws;
    }
    else if (p.network == "grpc")
    {
        json::object grpc;
        grpc["serviceName"] =
            p.path.empty() ? "grpc" : p.path;

        stream["grpcSettings"] = grpc;
    }
    else if (p.network == "h2")
    {
        if (p.streamSecurity != "tls")
            throw std::runtime_error("h2 必须 TLS");

        json::object http;
        http["path"] =
            p.path.empty() ? "/" : p.path;

        stream["httpSettings"] = http;
    }
    else if (p.network == "httpupgrade")
    {
        json::object http;
        http["path"] =
            p.path.empty() ? "/" : p.path;

        stream["httpSettings"] = http;
    }
    else if (p.network == "kcp")
    {
        stream["kcpSettings"] = json::object{};
    }
    else if (p.network == "xhttp")
    {
        json::object xhttp;
        xhttp["path"] =
            p.path.empty() ? "/" : p.path;

        stream["xhttpSettings"] = xhttp;
    }

    return stream;
}

json::object buildOutboundSettings(const ProxyItem& p)
{
    json::object settings;

    switch (p.configType)
    {
    case 3: // shadowsocks
        settings["servers"] = json::array({
            {
                {"address", p.address},
                {"port", p.port},
                {"method", p.security},
                {"password", p.id}
            }
        });
        break;

    case 5: // vless
        settings["vnext"] = json::array({
            {
                {"address", p.address},
                {"port", p.port},
                {"users", json::array({
                    {
                        {"id", p.id},
                        {"encryption", "none"}
                    }
                })}
            }
        });
        break;

    case 6: // trojan
        settings["servers"] = json::array({
            {
                {"address", p.address},
                {"port", p.port},
                {"password", p.id}
            }
        });
        break;

    default:
        throw std::runtime_error("未知 configType");
    }

    return settings;
}

std::string generateConfig(const ProxyItem& p)
{
    json::object config;

    /* inbound */
    config["inbounds"] = json::array({
        {
            {"listen","127.0.0.1"},
            {"port",1080},
            {"protocol","socks"},
            {"settings", {{"udp",false}}}
        }
    });

    /* outbound */
    json::object outbound;

    if (p.configType == 3) outbound["protocol"] = "shadowsocks";
    else if (p.configType == 5) outbound["protocol"] = "vless";
    else if (p.configType == 6) outbound["protocol"] = "trojan";
    else throw std::runtime_error("不支持协议类型");

    outbound["settings"] = buildOutboundSettings(p);
    outbound["streamSettings"] = buildStream(p);

    if (p.muxEnabled)
    {
        outbound["mux"] = {
            {"enabled",true},
            {"concurrency",8}
        };
    }

    config["outbounds"] = json::array({ outbound });

    std::ofstream file("temp_config.json");
    file << json::serialize(config);
    file.close();

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
             << r.security << ",";

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
        std::cout << "测试: " << p.lineNo<<"\t"<<p.remarks << std::endl;

        auto config = generateConfig(p);
        auto pi = startXray(config);

        long latency = testLatency();

        TestResult result;
        result.remarks = p.remarks;
        result.address = p.address;
        result.port = p.port;
        result.network = p.network;
        result.security = p.streamSecurity;

        if (p.configType == 3) result.protocol = "Shadowsocks";
        if (p.configType == 5) result.protocol = "VLESS";
        if (p.configType == 6) result.protocol = "Trojan";


        result.indexId = p.indexId;
        result.latency = latency > 0 ? latency : -1;
        writer.insert(p.indexId,
                      latency,
                      sortOrder++);

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

    /* 保存结果 */
    //writeResultsToDB(cfg.dbPath, results);
    saveResultsCSV(results, "test_result.csv");
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
