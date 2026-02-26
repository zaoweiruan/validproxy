/*
 * validProxy.cpp
 *
 *  Created on: 2026年2月12日
 *      Author: dsm
 */

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <sqlite3.h>
#include <winsock2.h>
#include <ws2tcpip.h>


#define WM_UPDATE_PROXY (WM_USER + 1)

HWND hListView;
HWND hMainWnd;

// ----------------- 数据结构 -----------------
struct ProxyConfig
{
    std::wstring indexId;
    std::wstring address;
    int port;
    std::wstring id;
    int alterId;
    std::wstring security;
    std::wstring network;
    std::wstring streamSecurity;
    std::wstring sni;
    std::wstring alpn;
    std::wstring publicKey;
    std::wstring shortId;
    std::wstring path;
    std::wstring host;
};

// ----------------- 去重 -----------------
std::vector<ProxyConfig> removeDuplicates(const std::vector<ProxyConfig>& input)
{
    std::vector<ProxyConfig> result;
    std::unordered_set<std::wstring> seen;

    for (const auto& p : input)
    {
        std::wstring key = p.address + L":" + std::to_wstring(p.port) + L":" +
            p.id + L":" + p.security + L":" + p.network;

        if (seen.insert(key).second)
            result.push_back(p);
    }
    return result;
}

// ----------------- SQLite 读取 -----------------
std::vector<ProxyConfig> readDatabase(const std::wstring& path)
{
    std::vector<ProxyConfig> proxies;
    sqlite3* db;
    if (sqlite3_open16(path.c_str(), &db) != SQLITE_OK)
        return proxies;

    const wchar_t* sql = L"SELECT IndexId, Address, Port, Id, AlterId, Security, Network, StreamSecurity, Sni, Alpn, PublicKey, ShortId, Path, RequestHost FROM ProfileItem";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare16_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        sqlite3_close(db);
        return proxies;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        ProxyConfig p;
        p.indexId = (const wchar_t*)sqlite3_column_text16(stmt, 0);
        p.address = (const wchar_t*)sqlite3_column_text16(stmt, 1);
        p.port = sqlite3_column_int(stmt, 2);
        p.id = (const wchar_t*)sqlite3_column_text16(stmt, 3);
        p.alterId = sqlite3_column_int(stmt, 4);
        p.security = (const wchar_t*)sqlite3_column_text16(stmt, 5);
        p.network = (const wchar_t*)sqlite3_column_text16(stmt, 6);
        p.streamSecurity = (const wchar_t*)sqlite3_column_text16(stmt, 7);
        p.sni = (const wchar_t*)sqlite3_column_text16(stmt, 8);
        p.alpn = (const wchar_t*)sqlite3_column_text16(stmt, 9);
        p.publicKey = (const wchar_t*)sqlite3_column_text16(stmt, 10);
        p.shortId = (const wchar_t*)sqlite3_column_text16(stmt, 11);
        p.path = (const wchar_t*)sqlite3_column_text16(stmt, 12);
        p.host = (const wchar_t*)sqlite3_column_text16(stmt, 13);
        proxies.push_back(p);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return proxies;
}

// ----------------- sing-box 配置生成 -----------------
void writeConfig(const ProxyConfig& p)
{
    std::ofstream file("config.json");
    file <<
R"({
  "log": { "level": "warn" },
  "inbounds": [{
    "type": "socks",
    "listen": "127.0.0.1",
    "listen_port": 10808
  }],
  "outbounds": [ )";
    // 动态生成 outbound
    std::ostringstream ss;
    if (p.security == L"vmess")
    {
        ss <<
R"({
  "type": "vmess",
  "tag": "proxy",
  "server": ")" << std::string(p.address.begin(), p.address.end()) << R"(",
  "server_port": )" << p.port << R"(,
  "uuid": ")" << std::string(p.id.begin(), p.id.end()) << R"(",
  "alter_id": )" << p.alterId << "\n}";
    }
    else if (p.security == L"vless")
    {
        ss <<
R"({
  "type": "vless",
  "tag": "proxy",
  "server": ")" << std::string(p.address.begin(), p.address.end()) << R"(",
  "server_port": )" << p.port << R"(,
  "uuid": ")" << std::string(p.id.begin(), p.id.end()) << R"("
})";
    }
    else if (p.security == L"trojan")
    {
        ss <<
R"({
  "type": "trojan",
  "tag": "proxy",
  "server": ")" << std::string(p.address.begin(), p.address.end()) << R"(",
  "server_port": )" << p.port << R"(,
  "password": ")" << std::string(p.id.begin(), p.id.end()) << R"("
})";
    }
    file << ss.str() << R"(],
  "route": { "final": "proxy" }
})";
}

// ----------------- 启动 sing-box -----------------
PROCESS_INFORMATION startSingBox()
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    std::wstring cmd = L"E:\\soft\\v2rayN-windows-64\\bin\\sing_box\\sing-box.exe run -c config.json";
    CreateProcessW(NULL, cmd.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    return pi;
}

// ----------------- 检测端口 -----------------
bool isPortOpen(int port = 10808)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    bool ok = connect(s, (sockaddr*)&addr, sizeof(addr)) == 0;
    closesocket(s);
    return ok;
}

// ----------------- 测速 -----------------
int testLatency(const std::wstring& url, int timeoutSeconds = 5)
{
    // 简单调用 curl 命令行
    std::wstring cmd = L"curl -x socks5h://127.0.0.1:10808 --connect-timeout " + std::to_wstring(timeoutSeconds) + L" -o NUL -s -w \"%{time_total}\" " + url;
    _wsystem(cmd.c_str());
    // 为模板演示，这里返回 0
    return 0;
}

// ----------------- 测速线程 -----------------
DWORD WINAPI TestThread(LPVOID lpParam)
{
    ProxyConfig* p = (ProxyConfig*)lpParam;
    writeConfig(*p);
    auto pi = startSingBox();

    // 等待端口就绪
    for (int i = 0; i < 50; ++i)
    {
        if (isPortOpen())
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    int latency = testLatency(L"https://www.google.com/generate_204", 5);

    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    PostMessage(hMainWnd, WM_UPDATE_PROXY, (WPARAM)p, (LPARAM)latency);
    return 0;
}

// ----------------- GUI 更新 -----------------
void updateListView(ProxyConfig* p, int latency)
{
    LVFINDINFO fi = {};
    fi.flags = LVFI_STRING;
    fi.psz = (LPWSTR)p->indexId.c_str();

    int idx = ListView_FindItem(hListView, -1, &fi);
    if (idx != -1)
    {
        std::wstring latencyStr = std::to_wstring(latency);
        ListView_SetItemText(hListView, idx, 5, latencyStr.data());
    }
}

// ----------------- Win32 窗口回调 -----------------
LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_UPDATE_PROXY:
        updateListView((ProxyConfig*)wParam, (int)lParam);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd,uMsg,wParam,lParam);
    }
    return 0;
}

// ----------------- WinMain -----------------
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow)
{
    // 初始化 Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    // 初始化窗口类、创建窗口、创建 ListView (略，可参考 Win32 ListView 示例)
    // hMainWnd 和 hListView 需要在这里初始化

    // 读取数据库
    std::vector<ProxyConfig> proxies = readDatabase(L"E:\\soft\\v2rayN-windows-64\\guiConfigs\\guiNDB.db");
    proxies = removeDuplicates(proxies);

    // 将 proxies 添加到 ListView (略)

    // 顺序启动测速线程
    for(auto& p : proxies)
    {
        CreateThread(NULL,0,TestThread,(LPVOID)&p,0,NULL);
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // 节点间隔
    }

    MSG msg;
    while(GetMessage(&msg,NULL,0,0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    WSACleanup();
    return (int)msg.wParam;
}



