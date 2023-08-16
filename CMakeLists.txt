cmake_minimum_required(VERSION 3.11)  # FetchContent is available in 3.11+
project(httpflow)
include_directories(/usr/local/include)
include(FetchContent)
set(ICU_INCLUDE_DIR /usr/local/opt/icu4c/include)
set(ICU_LIBRARY /usr/local/opt/icu4c/lib)

include_directories(${ICU_INCLUDE_DIR})
link_directories(${ICU_LIBRARY})

find_package(ICU REQUIRED)
# FetchContent_Declare(
#   json
#   GIT_REPOSITORY https://ghproxy.com/https://github.com/nlohmann/json.git
#   GIT_TAG v3.7.3
# )

# FetchContent_GetProperties(json)
# if(NOT json_POPULATED)
#   FetchContent_Populate(json)
#   add_subdirectory(${json_SOURCE_DIR} ${json_BINARY_DIR} EXCLUDE_FROM_ALL)
# endif()
add_subdirectory(external/nlohmann_json)
add_executable(httpflow http_flow.cpp stream_parser.cpp util.cpp data_link.cpp http_parser.cpp)
target_link_libraries(httpflow nlohmann_json::nlohmann_json pcap z pcre ${ICU_LIBRARY}/libicuuc.a ${ICU_LIBRARY}/libicudata.a)