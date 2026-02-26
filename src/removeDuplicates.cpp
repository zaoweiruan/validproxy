/*
 * removeDuplicates.cpp
 *
 *  Created on: 2026年2月26日
 *      Author: dsm
 */
#include <windows.h>
#include <iostream>
#include <sqlite3.h>
#include <string>

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow)
{
    sqlite3* db = nullptr;
    int rc;

    // 1. 打开数据库
    rc = sqlite3_open("E:\\soft\\v2rayN-windows-64\\guiConfigs\\guiNDB.db", &db);
    if (rc != SQLITE_OK) {
        std::cerr << "无法打开数据库: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }

    std::cout << "成功打开数据库 guidb.db\n\n";

    // 准备要执行的两条语句
    const char* sql_statements[] = {
        // 第一条：删除 StreamSecurity 为空 且 Subid 不等于特定值的记录
        "DELETE FROM profileitem "
        "WHERE StreamSecurity = '' "
        "AND Subid <> '5544178410297751350';",

        // 第二条：保留 address+port+Network 组合的第一条记录（按 rowid 最小保留）
        "DELETE FROM ProfileItem "
        "WHERE rowid NOT IN ("
        "    SELECT MIN(rowid) "
        "    FROM ProfileItem "
        "    GROUP BY address, port, Network"
        ");"
    };

    // 逐条执行
    for (size_t i = 0; i < sizeof(sql_statements) / sizeof(sql_statements[0]); ++i) {
        char* errMsg = nullptr;
        const char* sql = sql_statements[i];

        std::cout << "正在执行语句 " << (i + 1) << " ...\n";
        std::cout << sql << "\n";

        rc = sqlite3_exec(db, sql, nullptr, nullptr, &errMsg);

        if (rc != SQLITE_OK) {
            std::cerr << "SQL 执行失败: " << errMsg << std::endl;
            sqlite3_free(errMsg);
            // 可以选择 break; 或 continue; 看你是否要继续执行后续语句
            // 这里选择继续执行第二条
        } else {
            // 获取受影响的行数
            sqlite3_int64 affected = sqlite3_changes(db);
            std::cout << "执行成功，受影响行数: " << affected << "\n";
        }
        std::cout << "----------------------------------------\n";
    }

    // 最后提交（其实 sqlite3_exec 内部已经自动提交，除非你开了事务）
    std::cout << "\n所有清理操作已完成。\n";

    sqlite3_close(db);
    return 0;
}


