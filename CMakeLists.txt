cmake_minimum_required (VERSION 3.30)
set(CMAKE_VERBOSE_MAKEFILEON ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# 仅当未通过命令行指定时，在 CMakeLists.txt 开头添加
set(CMAKE_TOOLCHAIN_FILE "E:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "vcpkg toolchain file")
set(VCPKG_TARGET_TRIPLET "x64-mingw-static" CACHE STRING "vcpkg triplet")
project (validProxy)
set(XRAY_CORE_PATH "E:/eclipse_workspace/Xray-core")
include_directories(
    ${XRAY_CORE_PATH}
    "${PROJECT_SOURCE_DIR}/include"
     ${Protobuf_INCLUDE_DIR}  # 引入 Protobuf 头文件
)

set(CMAKE_BUILD_TYPE Debug)
set(Protobuf_INCLUDE_DIR "E:/vcpkg/installed/x64-mingw-static/include")
set(Protobuf_LIBRARY "E:/vcpkg/installed/x64-mingw-static/lib/libprotobuf.a")
set(Protobuf_PROTOC_EXECUTABLE "E:/vcpkg/installed/x64-mingw-static/tools/protobuf/protoc.exe")
set(Protobuf_VERSION "4.25.1") # 替换为你实际的 Protobuf 版本



#add_subdirectory(src/generated) # 添加生成的源文件目录


find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(CURL CONFIG REQUIRED)
#find_package(Protobuf 4.2 REQUIRED )
find_package(gRPC  REQUIRED COMPONENTS grpc grpc++)
#Boost 注意大小写，首字母必须大写
set(BOOST_ROOT "D:/boost_1_88_0")
find_package(Boost 1.88 REQUIRED COMPONENTS json filesystem process) 
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
# ========== 引入 Xray proto 生成的源文件（可选但推荐） ==========
# 如果需要编译时链接 proto 生成的 .cc 文件，添加以下代码

file(GLOB_RECURSE ALL_XRAY_PROTO_SRCS 
    "${XRAY_CORE_PATH}/*.pb.cc"
    "${XRAY_CORE_PATH}/*.grpc.pb.cc"
)
set(XRAY_PROTO_SRCS
    ${XRAY_CORE_PATH}/core/config.pb.cc
    ${XRAY_CORE_PATH}/app/proxyman/command/command.pb.cc
    ${XRAY_CORE_PATH}/app/proxyman/command/command.grpc.pb.cc
    ${XRAY_CORE_PATH}/app/proxyman/config.pb.cc
    ${XRAY_CORE_PATH}/app/proxyman/config.grpc.pb.cc
    ${XRAY_CORE_PATH}/common/protocol/user.pb.cc
        # 底层核心依赖
    ${XRAY_CORE_PATH}/common/serial/typed_message.pb.cc
    ${XRAY_CORE_PATH}/common/net/address.pb.cc
    ${XRAY_CORE_PATH}/common/net/port.pb.cc
    ${XRAY_CORE_PATH}/transport/internet/config.pb.cc
    ${XRAY_CORE_PATH}/common/protocol/server_spec.pb.cc
    ${XRAY_CORE_PATH}/common/protocol/user.pb.cc
    ${XRAY_CORE_PATH}/common/net/address.pb.cc
    ${XRAY_CORE_PATH}/proxy/vless/outbound/config.pb.cc
    ${XRAY_CORE_PATH}/proxy/vless/account.pb.cc
    ${XRAY_CORE_PATH}/transport/internet/reality/config.pb.cc
)



set (VALIDPROXY_SRCS
	    "${ALL_XRAY_PROTO_SRCS}"
        "${PROJECT_SOURCE_DIR}/src/validProxy.cpp"
)
set(XRAY_CURL_IMPORTER_SRCS
    	"${PROJECT_SOURCE_DIR}/src/xray_curl_importer.cpp"
)
add_executable(validProxy )
add_executable(removeDuplicates)
#add_executable(simpleTest "${PROJECT_SOURCE_DIR}/src/simple_main.cpp")
add_executable(xray_curl_import "${XRAY_CURL_IMPORTER_SRCS}")

#target_include_directories(validProxy PUBLIC E:/vcpkg/installed/x64-mingw-static/include)
set_target_properties(validProxy PROPERTIES SOURCES "${VALIDPROXY_SRCS}")

#target_include_directories(removeDuplicates PUBLIC E:/vcpkg/installed/x64-mingw-static/include)
set_target_properties(removeDuplicates PROPERTIES SOURCES "${PROJECT_SOURCE_DIR}/src/removeDuplicates.cpp")

set_target_properties(xray_curl_import PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")

set_target_properties(validProxy PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")
set_target_properties(removeDuplicates PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin")

target_link_libraries(xray_curl_import  PRIVATE 	CURL::libcurl Boost::json                                 
                                            )
target_link_libraries(validProxy PRIVATE CURL::libcurl Boost::json 
                                         Boost::filesystem
                                         Boost::process
											unofficial::sqlite3::sqlite3 
											ws2_32 
											${Protobuf_LIBRARY}
											gRPC::grpc           # gRPC 核心库
											gRPC::grpc++         # gRPC C++ 库
											
											)

#simple_main_1.cpp

#target_link_libraries(validProxy PRIVATE E:/vcpkg/installed/x64-mingw-static/debug/lib/libsqlite3.a Comctl32  ws2_32)
#target_link_libraries(removeDuplicates PRIVATE E:/vcpkg/installed/x64-mingw-static/debug/lib/libsqlite3.a Boost::json)
target_link_libraries(removeDuplicates PRIVATE unofficial::sqlite3::sqlite3 Boost::json)
target_compile_definitions(validProxy PRIVATE UNICODE _UNICODE)
target_compile_definitions(xray_curl_import PRIVATE UNICODE _UNICODE)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lstdc++ -std=c++17 -g -Wall  -O2 -mconsole -municode ")
