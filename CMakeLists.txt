cmake_minimum_required (VERSION 3.30)
set(CMAKE_VERBOSE_MAKEFILEON ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
project (validProxy)

set(CMAKE_BUILD_TYPE Debug)
set(BOOST_ROOT "D:/boost_1_88_0")
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(CURL CONFIG REQUIRED)
#Boost 注意大小写，首字母必须大写
find_package(Boost REQUIRED COMPONENTS json) 
message(STATUS "=== Boost 查找结果 ===")
message(STATUS "Boost_VERSION          : ${Boost_VERSION}")
message(STATUS "Boost_INCLUDE_DIRS     : ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost_LIBRARY_DIRS     : ${Boost_LIBRARY_DIRS}")
message(STATUS "Boost_LIBRARIES        : ${Boost_LIBRARIES}")
message(STATUS "Boost_JSON_FOUND       : ${Boost_JSON_FOUND}")
message(STATUS "Boost_JSON_LIBRARY     : ${Boost_JSON_LIBRARY}")     # 通常是完整库路径
message(STATUS "Boost_JSON_LIBRARY_DEBUG   : ${Boost_JSON_LIBRARY_DEBUG}")
message(STATUS "Boost_JSON_LIBRARY_RELEASE : ${Boost_JSON_LIBRARY_RELEASE}")

# 如果你想更精确地看 json 库文件
if(Boost_JSON_LIBRARY)
    message(STATUS "Boost.JSON 静态/动态库路径: ${Boost_JSON_LIBRARY}")
else()
    message(WARNING "Boost_JSON_LIBRARY 未定义，可能为 header-only 或查找有问题")
endif()
add_executable(validProxy)
add_executable(removeDuplicates)

#target_include_directories(validProxy PUBLIC E:/vcpkg/installed/x64-mingw-static/include)
set_target_properties(validProxy PROPERTIES SOURCES "${PROJECT_SOURCE_DIR}/src/validProxy.cpp")

#target_include_directories(removeDuplicates PUBLIC E:/vcpkg/installed/x64-mingw-static/include)
set_target_properties(removeDuplicates PROPERTIES SOURCES "${PROJECT_SOURCE_DIR}/src/removeDuplicates1.cpp")



set_target_properties(validProxy PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")
set_target_properties(removeDuplicates PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")

target_link_libraries(validProxy PRIVATE CURL::libcurl Boost::json unofficial::sqlite3::sqlite3 ws2_32)
#target_link_libraries(validProxy PRIVATE E:/vcpkg/installed/x64-mingw-static/debug/lib/libsqlite3.a Comctl32  ws2_32)
#target_link_libraries(removeDuplicates PRIVATE E:/vcpkg/installed/x64-mingw-static/debug/lib/libsqlite3.a Boost::json)
target_link_libraries(removeDuplicates PRIVATE unofficial::sqlite3::sqlite3 Boost::json)
target_compile_definitions(validProxy PRIVATE UNICODE _UNICODE)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lstdc++ -std=c++17 -g -Wall  -O2 -mconsole -municode ")
