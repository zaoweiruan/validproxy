/*
 * removeduplicates1.cpp
 *
 * Created on: 2026年2月26日
 * Author: dsm
 */

#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sqlite3.h>

// Boost.JSON (需要 Boost 1.75 或更高版本)
#include <boost/json.hpp>
namespace json = boost::json;

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow)
{
    std::string config_path = "config.json";

    // 1. 读取配置文件
    std::ifstream ifs(config_path);
    if (!ifs.is_open()) {
        std::cerr << "无法打开配置文件: " << config_path << std::endl;
        return 1;
    }

    std::string content((std::istreambuf_iterator<char>(ifs)),
                         std::istreambuf_iterator<char>());

    json::value jv;
    try {
        jv = json::parse(content);
    } catch (const std::exception& e) {
        std::cerr << "JSON 解析失败: " << e.what() << std::endl;
        return 1;
    }

    // 2. 提取数据库路径（带默认值）
    std::string db_path = "guiNDB.db";

    if (jv.is_object()) {
        json::object const& root = jv.as_object();

        if (auto it = root.find("database"); it != root.end()) {
            json::value const& db_val = it->value();
            if (db_val.is_object()) {
                json::object const& db_obj = db_val.as_object();

                if (auto path_it = db_obj.find("path"); path_it != db_obj.end()) {
                    json::value const& path_val = path_it->value();
                    if (path_val.is_string()) {
                        db_path = path_val.as_string().c_str();
                    }
                }
            }
        }
    }

    std::cout << "数据库路径: " << db_path << "\n\n";

    // 3. 提取 SQL 语句数组
    std::vector<std::string> statements;

    if (jv.is_object()) {
        json::object const& root = jv.as_object();

        if (auto it = root.find("sql_statements"); it != root.end()) {
            json::value const& arr_val = it->value();
            if (arr_val.is_array()) {
                json::array const& arr = arr_val.as_array();

                for (json::value const& item : arr) {
                    if (item.is_string()) {
                        statements.push_back(item.as_string().c_str());
                    }
                }
            }
        }
    }

    if (statements.empty()) {
        std::cerr << "配置文件中没有有效的 SQL 语句\n";
        return 1;
    }

    std::cout << "共读取到 " << statements.size() << " 条 SQL 语句\n\n";

    // 4. 打开 SQLite 数据库
    sqlite3* db = nullptr;
    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc != SQLITE_OK) {
    	std::cerr << "无法打开数据库: "
    	              << sqlite3_errstr(rc) << std::endl;
        if (db) sqlite3_close(db);
        return 1;
    }

    std::cout << "数据库打开成功\n\n";

    // 5. 逐条执行 SQL
    for (size_t i = 0; i < statements.size(); ++i) {
        const std::string& sql = statements[i];
        std::cout << "执行语句 " << (i + 1) << ":\n" << sql << "\n";

        char* errMsg = nullptr;
        rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);

        if (rc != SQLITE_OK) {
            std::cerr << "执行失败: " << (errMsg ? errMsg : "未知错误") << std::endl;
            if (errMsg) sqlite3_free(errMsg);
            // 可选择在此 break; 或 continue; 目前選擇繼續執行
        } else {
            sqlite3_int64 changes = sqlite3_changes(db);
            std::cout << "成功，受影响行数: " << changes << "\n";
        }
        std::cout << "----------------------------------------\n";
    }

    sqlite3_close(db);
    std::cout << "\n所有清理操作完成。\n";

    return 0;
}
