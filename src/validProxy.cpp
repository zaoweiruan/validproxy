#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <windows.h>

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
#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <grpcpp/grpcpp.h>
#include "app/proxyman/command/command.grpc.pb.h"
#include "app/proxyman/command/command.pb.h"
#include "core/config.pb.h"
#include <google/protobuf/util/json_util.h>
#include <google/protobuf/message.h>
#include "Profileitem.h"
#pragma comment(lib, "sqlite3.lib")
#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "grpc++.lib")
#pragma comment(lib, "libprotobuf.lib")

namespace json = boost::json;
namespace fs = boost::filesystem;
namespace bp = boost::process;
using namespace xray::app::proxyman::command;
using namespace db::models;
using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

// 代理项结构体（保持原有定义）
//struct ProxyItem {
//    int configType; // 3=SS, 4=VMess, 5=VLESS, 6=Trojan
//    std::string address;
//    int port;
//    std::string id; // uuid 或 password
//    std::string security; // method / cipher
//    std::string flow; // 新增 (VLESS Vision)
//    std::string network;
//    std::string streamSecurity;
//    std::string remarks;
//    std::string indexId;
//    // 通用
//    std::string requestHost;
//    std::string path;
//    std::string allowInsecure;
//    std::string sni;
//    std::string alpn;
//    // TLS/Reality
//    std::string fingerprint;
//    std::string publicKey;
//    std::string shortId;
//    std::string spiderX;
//    // TCP header
//    std::string tcpHeaderType; // none/http
//    // gRPC
//    int grpcMultiMode = 0;
//    // KCP
//    int kcpMtu = 1350;
//    int kcpTti = 20;
//    int kcpUplink = 12;
//    int kcpDownlink = 20;
//    int kcpCongestion = 0;
//	int kcpReadBufferSize = 2;
//	int kcpWriteBufferSize = 2;
//
//    std::string kcpHeaderType = "none";
//    int muxEnabled;
//    int lineNo;
//};

// 测试结果结构体（保持原有定义）
struct TestResult {
    std::string remarks;
    std::string address;
    int port;
    std::string protocol;
    std::string network;
    std::string security;
    std::string indexId;
    long latency; // -1 表示失败
    std::string jsonConfig;
    // 新增
    int curlCode = 0;
    long httpCode = 0;
    std::string errorMessage;
    std::string diagnosis;
};

struct AppConfig {
    std::string dbPath;
    std::string proxy_query;
};

// CURL测试详情结构体（修复时延单位错误）
struct CurlTestDetail {
    long latency = -1;
    CURLcode curlCode = CURLE_OK;
    long httpCode = 0;
    std::string errorMessage;
    std::string diagnosis;
    double dns_ms;    // 修正：改为*1000
    double tcp_ms;    // 修正：改为*1000
    double tls_ms;    // 修正：改为*1000
    double total_ms;  // 修正：改为*1000
};

// 结果写入器类（保持原有定义）
class ResultWriter {
public:
    ResultWriter(const std::string& dbPath) {
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

    void insert(const TestResult& detail, int sortOrder) {
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, detail.indexId.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, detail.latency);
        sqlite3_bind_double(stmt, 3, 0.0); // Speed 暂时为 0
        sqlite3_bind_int(stmt, 4, sortOrder);

        std::string msg;
        if (detail.latency > 0)
            msg = "OK";
        else
            msg = detail.diagnosis;

        sqlite3_bind_text(stmt, 5, msg.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "写入失败: " << sqlite3_errmsg(db) << std::endl;
        }
    }

    ~ResultWriter() {
        if (stmt) sqlite3_finalize(stmt);
        if (db) sqlite3_close(db);
    }

private:
    sqlite3* db = nullptr;
    sqlite3_stmt* stmt = nullptr;
};

// 构建流配置（通用，补充REALITY配置）
json::object buildStreamSettings(const Profileitem& p) {
    json::object streamSettings;
    streamSettings["network"] = json::value(p.network);
    streamSettings["security"] = json::value(p.streamsecurity);

    // TLS配置
    if (p.streamsecurity == "tls") {
        json::object tlsSettings;
        tlsSettings["allowInsecure"] = json::value(p.allowinsecure == "1");
        if (!p.sni.empty()) {
            tlsSettings["serverName"] = json::value(p.sni);
        }
        if (!p.alpn.empty()) {
            std::vector<std::string> alpnList;
            std::stringstream ss(p.alpn);
            std::string item;
            while (std::getline(ss, item, ',')) {
                alpnList.push_back(item);
            }
            json::array alpnArr;
            for (const auto& a : alpnList) {
                alpnArr.push_back(json::value(a));
            }
            tlsSettings["alpn"] = alpnArr;
        }
        // 补充fingerprint
        if (!p.fingerprint.empty()) {
            tlsSettings["fingerprint"] = json::value(p.fingerprint);
        }
        streamSettings["tlsSettings"] = tlsSettings;
    }

    // ========== 关键修复：补充REALITY配置 ==========
    else if (p.streamsecurity == "reality") {
        json::object realitySettings;
        // REALITY必需参数校验
        if (p.publickey.empty()) {
            throw std::runtime_error("REALITY配置错误：publicKey不能为空");
        }
        if (p.sni.empty()) {
            throw std::runtime_error("REALITY配置错误：sni(serverName)不能为空");
        }

        // 基础REALITY配置
        realitySettings["publicKey"] = json::value(p.publickey);
        realitySettings["serverName"] = json::value(p.sni);

        // 可选参数
        if (!p.shortid.empty()) {
            realitySettings["shortId"] = json::value(p.shortid);
        }
        if (!p.spiderx.empty()) {
            realitySettings["spiderX"] = json::value(p.spiderx);
        }
        else
        	{realitySettings["spiderX"] ="";}

        if (!p.mldsa65verify.empty()) {
            realitySettings["mldsa65Verify"] = json::value(p.mldsa65verify);
        }
        else
        	{realitySettings["mldsa65Verify"] ="";}

        if (!p.fingerprint.empty()) {
            realitySettings["fingerprint"] = json::value(p.fingerprint);
        }
        else
		{
			realitySettings["fingerprint"] = "chrome";
		}

        streamSettings["realitySettings"] = realitySettings;
    }

    // gRPC配置
    if (p.network == "grpc") {
        json::object grpcSettings;
        grpcSettings["serviceName"] = json::value(p.path);
        grpcSettings["multiMode"] = p.grpcMultiMode == 1;
        grpcSettings["idle_timeout"] = 60;
        grpcSettings["health_check_timeout"] = 20;
        grpcSettings["permit_without_stream"] = false;
        grpcSettings["initial_windows_size"] = 0;
        streamSettings["grpcSettings"] = grpcSettings;
    }

    // WS配置
    if (p.network == "ws") {
        json::object wsSettings;
        if (!p.path.empty()) {
            wsSettings["path"] = json::value(p.path);
        }
        if (!p.requesthost.empty()) {
            json::object headers;
            headers["host"] = json::value(p.requesthost);
            wsSettings["headers"] = headers;
        }
        streamSettings["wsSettings"] = wsSettings;
    }
    // xhttp配置
    if (p.network == "xhttp") {
        json::object xhttpSettings;
        if (!p.path.empty()) {
        	xhttpSettings["path"] = json::value(p.path);
        }
        if (!p.requesthost.empty()) {
            json::object headers;
            headers["host"] = json::value(p.requesthost);
         }
        if (!p.headertype.empty()) {
            json::object headers;
            headers["mode"] = json::value(p.headertype);
         }
        streamSettings["xhttpSettings"] = xhttpSettings;
    }
    // kcp配置
        if (p.network == "kcp") {
        	json::object kcpSettings;
        	kcpSettings["mtu"] = p.kcpMtu;
        	kcpSettings["tti"] = p.kcpTti;
        	kcpSettings["uplinkCapacity"] = p.kcpUplink;
        	kcpSettings["downlinkCapacity"] = p.kcpDownlink;
        	kcpSettings["congestion"] = p.kcpCongestion == 1;
        	kcpSettings["readBufferSize"] = p.kcpReadBufferSize;
        	kcpSettings["writeBufferSize"] = p.kcpWriteBufferSize;
		if (!p.headertype.empty()) {
			kcpSettings["header"] = json::object { { "type", json::value(
					p.kcpHeaderType) } };
		}
			streamSettings["kcpSettings"] = kcpSettings;
        }
    return streamSettings;
	}

bool isValidNetwork(const std::string& network) {
    static const std::set<std::string> valid = {
        "tcp","ws","grpc","h2","httpupgrade","kcp","xhttp"
    };
    return valid.count(network) > 0;
}

// 生成VLESS Outbound配置（匹配xray标准格式，修正字段错误）
json::object buildVLESSOutbound(const Profileitem& p, const std::string& outboundTag) {
    json::object outbound;

    // 基础字段
    outbound["tag"] = json::value(outboundTag);
    outbound["protocol"] = json::value("vless");

    // settings字段（核心）
    json::object settings;
    json::array vnextArr;
    json::object vnext;

    vnext["address"] = json::value(p.address);
    vnext["port"] = json::value(std::stoi(p.port));

    // users数组
    json::array usersArr;
    json::object user;
    user["id"] = json::value(p.id);
    user["email"] = json::value("t@t.tt");
    // ========== 关键修复：VLESS协议字段修正 ==========
    // VLESS中只有encryption字段，无security字段，且值固定为none
    user["encryption"] = json::value("none");
    // 可选：flow字段（VLESS Vision）
    if (!p.flow.empty()) {
        user["flow"] = json::value(p.flow);
    }
//    else
//       {user["flow"] = "xtls-rprx-direct";}

    if (!p.security.empty()) {
        user["security"] = json::value("auto");
    }
    usersArr.push_back(user);

    vnext["users"] = usersArr;
    vnextArr.push_back(vnext);
    settings["vnext"] = vnextArr;
    outbound["settings"] = settings;

    // streamSettings字段
    json::object streamSettings = buildStreamSettings(p);
    outbound["streamSettings"] = streamSettings;

    // mux配置
    json::object mux;
    mux["enabled"] = p.muxEnabled == 1;
    mux["concurrency"] = -1;
    outbound["mux"] = mux;

    return outbound;
}

// 生成VMess Outbound配置（匹配xray标准格式）
json::object buildVMessOutbound(const Profileitem& p, const std::string& outboundTag) {
    json::object outbound;

    outbound["tag"] = json::value(outboundTag);
    outbound["protocol"] = json::value("vmess");

    json::object settings;
    json::array vnextArr;
    json::object vnext;

    vnext["address"] = json::value(p.address);
    vnext["port"] = json::value(std::stoi(p.port));

    json::array usersArr;
    json::object user;
    user["id"] = json::value(p.id);
    user["alterId"] = 0;
    user["security"] = json::value(p.security.empty() ? "auto" : p.security);
    usersArr.push_back(user);

    vnext["users"] = usersArr;
    vnextArr.push_back(vnext);
    settings["vnext"] = vnextArr;
    outbound["settings"] = settings;

    // streamSettings（复用VLESS的逻辑）
    json::object streamSettings = buildStreamSettings(p);
    outbound["streamSettings"] = streamSettings;

    // mux配置
    json::object mux;
    mux["enabled"] = p.muxEnabled == 1;
    mux["concurrency"] = -1;
    outbound["mux"] = mux;

    return outbound;
}

// 生成Shadowsocks Outbound配置（匹配xray标准格式）
json::object buildSSOutbound(const Profileitem& p, const std::string& outboundTag) {
    json::object outbound;

    outbound["tag"] = json::value(outboundTag);
    outbound["protocol"] = json::value("shadowsocks");

    json::object settings;
    json::array serversArr;
    json::object server;

    server["address"] = json::value(p.address);
    server["port"] = json::value(std::stoi(p.port));
    server["method"] = json::value(p.security);
    server["password"] = json::value(p.id);

    serversArr.push_back(server);
    settings["servers"] = serversArr;
    outbound["settings"] = settings;

    // streamSettings
    json::object streamSettings = buildStreamSettings(p);
    outbound["streamSettings"] = streamSettings;

    // mux配置
    json::object mux;
    mux["enabled"] = p.muxEnabled == 1;
    mux["concurrency"] = -1;
    outbound["mux"] = mux;

    return outbound;
}

// 生成Trojan Outbound配置（匹配xray标准格式）
json::object buildTrojanOutbound(const Profileitem& p, const std::string& outboundTag) {
    json::object outbound;

    outbound["tag"] = json::value(outboundTag);
    outbound["protocol"] = json::value("trojan");

    json::object settings;
    json::array serversArr;
    json::object server;

    server["address"] = json::value(p.address);
    server["port"] = json::value(std::stoi(p.port));
    server["password"] = json::value(p.id);

    serversArr.push_back(server);
    settings["servers"] = serversArr;
    outbound["settings"] = settings;

    // streamSettings
    json::object streamSettings = buildStreamSettings(p);
    outbound["streamSettings"] = streamSettings;

    // mux配置
    json::object mux;
    mux["enabled"] = p.muxEnabled == 1;
    mux["concurrency"] = -1;
    outbound["mux"] = mux;

    return outbound;
}

// 生成完整的Xray配置文件（增加配置校验）
//std::string generateXrayConfigJSON(const Profileitem& p, const std::string& outboundTag){
json::value generateXrayConfigJSON(const Profileitem& p, const std::string& outboundTag){
    // ========== 前置校验 ==========
    if (p.address.empty()) {
        throw std::runtime_error("代理地址不能为空");
    }
    if ((std::stoi(p.port) <= 0 || std::stoi(p.port) > 65535)) {
        throw std::runtime_error("无效的端口号: " + p.port);
    }
    if (p.id.empty()) {
        throw std::runtime_error("代理ID/密码不能为空");
    }

    // REALITY特殊校验
    if (p.streamsecurity == "reality") {
        if (p.publickey.empty()) {
            throw std::runtime_error("REALITY配置缺少publicKey");
        }
        if (p.sni.empty()) {
            throw std::runtime_error("REALITY配置缺少sni(serverName)");
        }
    }

    json::object root;
    json::array outboundsArr;

    // 根据协议类型构建不同的outbound
    json::object outbound;
    switch (std::stoi(p.configtype)) {
        case 3: // Shadowsocks
            outbound = buildSSOutbound(p, outboundTag);
            break;
        case 1: // VMess
            outbound = buildVMessOutbound(p, outboundTag);
            break;
        case 5: // VLESS
            outbound = buildVLESSOutbound(p, outboundTag);
            break;
        case 6: // Trojan
            outbound = buildTrojanOutbound(p, outboundTag);
            break;
        default:
            throw std::runtime_error("不支持的协议类型: " + p.configtype);
    }
    
    outboundsArr.push_back(outbound);
    root["outbounds"] = outboundsArr;

    // 序列化为格式化的JSON字符串
    std::string jsonStr = json::serialize(root);

    // 保存到文件
//    std::ofstream file(filename);
//    if (!file) {
//        throw std::runtime_error("无法创建配置文件: " + filename);
//    }
//    file << jsonStr;
//    file.close();

    //std::cout << "\n=== 生成Xray配置JSON ===\n" << jsonStr << "\n===============================\n" << std::endl;

    
    return root;
    //return jsonStr;
}

// ========== 原有代码（略作调整） ==========
// Xray gRPC客户端类（保留，用于动态移除outbound）
class XrayGrpcClient {
public:
    explicit XrayGrpcClient(std::shared_ptr<Channel> channel)
        : stub_(HandlerService::NewStub(channel)) {}

    // 移除Outbound方法
    int RemoveOutbound(const std::string& outboundTag) {
        xray::app::proxyman::command::RemoveOutboundRequest request;
        request.set_tag(outboundTag);

        grpc::ClientContext context;
        context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(2));

        xray::app::proxyman::command::RemoveOutboundResponse response;
        grpc::Status rpc_status = stub_->RemoveOutbound(&context, request, &response);

        if (!rpc_status.ok()) {
            std::cerr << "移除Outbound失败: " << rpc_status.error_message() << std::endl;
            return -1;
        }

        return 0;
    }

private:
    std::unique_ptr<xray::app::proxyman::command::HandlerService::Stub> stub_;
};

// 保存结果到CSV（保持原有定义）
void saveResultsCSV(const std::vector<TestResult>& results, const std::string& filename) {
    std::ofstream file(filename, std::ios::out | std::ios::trunc);
    file << "Remarks,Address,Port,Protocol,Network,Security,Latency(ms),Status,Diagnosis\n";
    for (const auto& r : results) {
        file << "\"" << r.remarks << "\","
             << "\"" << r.address << "\","
             << r.port << ","
             << "\"" << r.protocol << "\","
             << "\"" << r.network << "\","
             << "\"" << r.security << "\","
             << r.latency << ","
             << (r.latency > 0 ? "OK" : "FAILED") << ","
             << "\"" << r.diagnosis << "\"\n";
    }
    file.close();
}

// 保存结果到JSON（保持原有定义）
void saveResultsJSON(const std::vector<TestResult>& results, const std::string& filename) {
    json::array arr;
    for (const auto& r : results) {
        json::object obj;
        obj["remarks"] = json::value(r.remarks);
        obj["address"] = json::value(r.address);
        obj["port"] = r.port;
        obj["protocol"] = json::value(r.protocol);
        obj["network"] = json::value(r.network);
        obj["security"] = json::value(r.security);
        obj["latency"] = r.latency;
        obj["status"] = json::value(r.latency > 0 ? "OK" : "FAILED");
        obj["jsonConfig"] = json::value(r.jsonConfig);
        obj["curlCode"] = r.curlCode;
        obj["httpCode"] = r.httpCode;
        obj["errorMessage"] = json::value(r.errorMessage);
        obj["diagnosis"] = json::value(r.diagnosis);
        arr.push_back(obj);
    }
    std::ofstream file(filename, std::ios::out | std::ios::trunc);
    file << json::serialize(arr);
    file.close();
}

// 加载应用配置（保持原有定义）
AppConfig loadAppConfig(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file)
        throw std::runtime_error("无法打开 config.json");

    std::stringstream buffer;
    buffer << file.rdbuf();
    boost::json::value json = boost::json::parse(buffer.str());

    AppConfig cfg;
    cfg.dbPath = json.at("database").at("path").as_string().c_str();
    cfg.proxy_query = json.at("proxy_query").as_string().c_str();

    return cfg;
}

// 从数据库加载代理列表（保持原有定义）
std::vector<Profileitem> loadProxiesFromConfig(const AppConfig& cfg) {
    std::vector<Profileitem> list;
    sqlite3* db = nullptr;

    try {
        int rc = sqlite3_open(cfg.dbPath.c_str(), &db);
        if (rc != SQLITE_OK) {
            std::string err = db ? sqlite3_errmsg(db) : "未知错误";
            throw std::runtime_error("无法打开数据库: " + cfg.dbPath + " 错误: " + err);
        }

        const char* query = cfg.proxy_query.c_str();
        std::cout << "执行SQL: " << query << std::endl;

        sqlite3_stmt* stmt = nullptr;
        rc = sqlite3_prepare_v2(db, query, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            throw std::runtime_error("SQL prepare 失败: " + std::string(sqlite3_errmsg(db)));
        }

        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {

        	auto p= Profileitem::fromStmt(stmt);

        	p.network = (p.network.empty() &&p.configtype == "3") ? "tcp" : p.network; // 默认tcp

            if (!isValidNetwork(p.network)) {
                std::cerr << "跳过无效网络类型: " << p.network << " (" << p.remarks << ")" << std::endl;
                continue;
            }

            list.push_back(std::move(p));
        }

        if (rc != SQLITE_DONE) {
            throw std::runtime_error("SQL step 执行异常: " + std::string(sqlite3_errmsg(db)));
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        std::cout << "成功加载代理数量: " << list.size() << std::endl;
        return list;
    }
    catch (...) {
        if (db)
            sqlite3_close(db);
        throw;
    }
}

// CURL错误诊断（保持原有定义）
std::string diagnoseCurl(CURLcode code) {
    switch (code) {
        case CURLE_COULDNT_RESOLVE_HOST:
            return "DNS 解析失败";
        case CURLE_COULDNT_CONNECT:
            return "TCP 连接失败（端口未开放或被拦截）";
        case CURLE_OPERATION_TIMEDOUT:
            return "连接超时（可能被墙或丢包）";
        case CURLE_SSL_CONNECT_ERROR:
            return "TLS 握手失败";
        case CURLE_PEER_FAILED_VERIFICATION:
            return "证书校验失败/CA证书验证失败";
        case CURLE_GOT_NOTHING:
            return "服务器未返回数据";
        case CURLE_SSL_CIPHER:
            return "TLS加密套件不兼容";
        case CURLE_RECV_ERROR:
            return "接收数据失败";
        case CURLE_SEND_ERROR:
            return "发送数据失败";
        default:
            return "未知连接错误: " + std::string(curl_easy_strerror(code));
    }
}

// 测试代理时延（保持原有定义）
CurlTestDetail testLatency(const std::string& proxyTag = "proxy-test") {
    CurlTestDetail detail;
    CURL* curl = curl_easy_init();

    if (!curl) {
        detail.diagnosis = "CURL 初始化失败";
        return detail;
    }

    char errbuf[CURL_ERROR_SIZE] = { 0 };
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.google.com/generate_204");
    curl_easy_setopt(curl, CURLOPT_PROXY, "socks5://127.0.0.1:1082");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 8L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char*, size_t s, size_t n, void*) {
        return s * n;
    });
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    auto start = std::chrono::steady_clock::now();
    detail.curlCode = curl_easy_perform(curl);
    auto end = std::chrono::steady_clock::now();

    if (detail.curlCode != CURLE_OK) {
        detail.errorMessage = curl_easy_strerror(detail.curlCode);
        if (strlen(errbuf) > 0)
            detail.errorMessage += std::string(" | ") + errbuf;
        detail.diagnosis = diagnoseCurl(detail.curlCode);
        curl_easy_cleanup(curl);
        return detail;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &detail.httpCode);
    if (detail.httpCode != 204) {
        detail.diagnosis = "HTTP 状态异常: " + std::to_string(detail.httpCode);
        curl_easy_cleanup(curl);
        return detail;
    }

    double dns = 0, tcp = 0, tls = 0, total = 0;
    curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME, &dns);
    curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &tcp);
    curl_easy_getinfo(curl, CURLINFO_APPCONNECT_TIME, &tls);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total);

    detail.dns_ms = dns * 1000;
    detail.tcp_ms = tcp * 1000;
    detail.tls_ms = tls * 100;
    detail.total_ms = total * 100;
   // detail.latency = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    detail.latency = detail.total_ms;

    curl_easy_cleanup(curl);
    return detail;
}

// ========== 新增：CURL POST Xray API 函数 ==========
// 直接通过HTTP POST将JSON配置发送到Xray API
bool curlPostXrayApi(const std::string& api_url, const std::string& json_config) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "CURL初始化失败" << std::endl;
        return false;
    }

    // 设置POST参数
    curl_easy_setopt(curl, CURLOPT_URL, api_url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_config.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, json_config.length());

    // 设置请求头
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // 超时设置
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    // 禁止输出响应内容
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char*, size_t s, size_t n, void*) {
        return s * n;
    });

    // 执行请求
    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    // 清理资源
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    // 检查结果
    if (res != CURLE_OK) {
        std::cerr << "Xray API请求失败: " << curl_easy_strerror(res) << std::endl;
        return false;
    }

    if (http_code < 200 || http_code >= 300) {
        std::cerr << "Xray API返回错误状态码: " << http_code << std::endl;
        return false;
    }

    return true;
}

bool add_outbound(const json::value& config, const std::string& server = "127.0.0.1:10086") {
    // 创建临时文件
//    auto temp_path = fs::temp_directory_path() / fs::unique_path("xray-%%%%-%%%%.json");
//    std::string temp_file = temp_path.string();
//
//    {
//        std::ofstream ofs(temp_file);
//        ofs << json::serialize(config);
//    }

    // 执行命令
	std::string cmd="echo " + json::serialize(config) + " | xray api ado --server=" + server +" stdin:";
   // std::string cmd = "xray api ado --server=" + server + " " + temp_file;
    std::cout << "Executing: " << cmd << std::endl;

    int result = std::system(cmd.c_str());

    // 清理
    //fs::remove(temp_path);

    return result == 0;
}

// ========== 主函数（核心修改） ==========
int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    curl_global_init(CURL_GLOBAL_ALL);

    try {
        // 1. 加载配置和代理列表
        AppConfig cfg = loadAppConfig("config.json");
        auto proxies = loadProxiesFromConfig(cfg);

        // 2. 初始化结果存储
        std::vector<TestResult> results;
        ResultWriter writer(cfg.dbPath);
        int sortOrder = 1;
        int proxiesCounts = proxies.size();

        // 3. 初始化Xray gRPC客户端（仅用于移除outbound）
        XrayGrpcClient xrayClient(grpc::CreateChannel(
            "127.0.0.1:10086",
            grpc::InsecureChannelCredentials()
        ));
        // Xray API地址（默认）
        const std::string xray_api_url = "http://127.0.0.1:10086/app/proxyman/outbound/add";
        long lineNo=1;
        // 4. 遍历测试每个代理
        for (auto& p : proxies) {
            TestResult result;
            std::string outboundTag = "proxy-test";
            std::string configFilename = "outbound.json";

            // 设置基础信息
            if (std::stoi(p.configtype) == 3) result.protocol = "Shadowsocks";
            if (std::stoi(p.configtype) == 1) result.protocol = "VMESS";
            if (std::stoi(p.configtype) == 5) result.protocol = "VLESS";
            if (std::stoi(p.configtype) == 6) result.protocol = "Trojan";

            std::cout << "测试: " <<lineNo++ << "/" << proxiesCounts << "\t" << p.remarks << "\t" << p.address << "\t" << result.protocol << std::endl;

            try {
                // ========== 核心修改：生成Xray配置JSON（不生成文件） ==========
                //std::string configJson = generateXrayConfigJSON(p, outboundTag);
                auto configJson = generateXrayConfigJSON(p, outboundTag);
				if (!add_outbound(configJson)) {
					throw std::runtime_error("添加Outbound失败");
                }

                // ========== 核心修改：通过CURL POST直接导入配置 ==========
//                std::cout << "调用Xray API导入配置: " << xray_api_url << std::endl;
//                bool post_success = curlPostXrayApi(xray_api_url, configJson);
//                if (!post_success) {
//                    throw std::runtime_error("调用Xray API导入配置失败");
//                }

                // 等待配置生效
                std::this_thread::sleep_for(std::chrono::milliseconds(800));

                // 测试连通性
                auto detail = testLatency(outboundTag);
                result.latency = detail.latency;
                result.curlCode = detail.curlCode;
                result.httpCode = detail.httpCode;
                result.errorMessage = detail.errorMessage;
                result.diagnosis = detail.diagnosis;
                result.remarks = p.remarks;
                result.address = p.address;
                result.port = std::stoi(p.port);
                result.network = p.network;
                result.security = p.streamsecurity;
                result.indexId = p.indexid;
                result.jsonConfig = json::serialize(configJson);

                // 写入结果
                writer.insert(result, sortOrder++);
                results.push_back(result);

                // 输出测试结果
                if (detail.latency > 0) {
                    std::cout << " 成功 | dns= " << detail.dns_ms << " ms | tcp= " << detail.tcp_ms << " ms | tls= " << detail.tls_ms << " ms | 总时延= " << detail.latency << " ms\n";
                }
                else {
                    std::cout << " 失败 | 错误: " << detail.errorMessage << " | 诊断: " << detail.diagnosis << "\n";
                }

                // 移除测试的Outbound


                int removeRet = xrayClient.RemoveOutbound(outboundTag);
                if (removeRet != 0) {
                    std::cerr << "警告：移除Outbound失败，标签: " << outboundTag << std::endl;
                }

                // 删除临时配置文件
               // DeleteFileA(configFilename.c_str());

                std::this_thread::sleep_for(std::chrono::milliseconds(300));
                std::cout << "----------------------\n";
            }
            catch (const std::exception& e) {
                std::cerr << "测试失败: " << e.what() << "\n";
                result.latency = 0;
                result.diagnosis = "配置/调用错误: " + std::string(e.what());
                results.push_back(result);
                // 清理
                xrayClient.RemoveOutbound(outboundTag);
                continue;
            }
        }

        // 保存结果
        //saveResultsJSON(results, "test_result.json");
        saveResultsCSV(results, "test_result.csv");
        std::cout << "测试完成，结果已保存\n";

    }
    catch (const std::exception& e) {
        std::cerr << "程序异常: " << e.what() << std::endl;
        curl_global_cleanup();
        return -1;
    }

    curl_global_cleanup();
    //system("pause");
    return 0;
}
