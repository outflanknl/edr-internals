cmake_minimum_required(VERSION 3.18)

set(DEV_ID "26N92YPF65")
set(BUNDLE_ID "nl.outflank.nedump")
set(EXT_BUNDLE_ID "${BUNDLE_ID}.extension")

project(nixedr LANGUAGES CXX OBJC OBJCXX)

set(CMAKE_CXX_STANDARD 11)

string(APPEND CMAKE_CXX_FLAGS " -Wall -Wextra")
string(APPEND CMAKE_CXX_FLAGS_RELEASE " -Werror")

add_definitions(-DBUNDLE_ID="${BUNDLE_ID}")
add_definitions(-DEXT_BUNDLE_ID="${EXT_BUNDLE_ID}")

add_subdirectory("external/nlohmann_json" EXCLUDE_FROM_ALL)

add_executable(ESDump "ESDump/esdump.cpp")
add_executable(NEDump "NEDump/nedump.m")
add_executable(${EXT_BUNDLE_ID} "NEDump/netext/content_filter.mm")

add_dependencies(NEDump ${EXT_BUNDLE_ID})

target_include_directories(ESDump PRIVATE
    "ESDump"
    "external/nlohmann_json/include"
)

target_include_directories(NEDump PRIVATE "NEDump")

target_include_directories(${EXT_BUNDLE_ID} PRIVATE
    "NEDump/netext"
    "external/nlohmann_json/include"
)

find_library(CORE_FOUNDATION CoreFoundation REQUIRED)
find_library(NETWORK_EXT NetworkExtension REQUIRED)

target_link_libraries(NEDump PRIVATE
    ${NETWORK_EXT}
    ${CORE_FOUNDATION}
)

target_link_libraries(ESDump PRIVATE
    nlohmann_json::nlohmann_json
    ${CORE_FOUNDATION}
    EndpointSecurity
    libbsm.tbd
)

target_link_libraries(${EXT_BUNDLE_ID} PRIVATE
    ${CORE_FOUNDATION}
    ${NETWORK_EXT}
    libbsm.tbd
)

set_target_properties(ESDump PROPERTIES
    XCODE_ATTRIBUTE_CLANG_ENABLE_MODULES YES
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "ESDump/entitlements"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_LIST_DIR}/ESDump/Info.plist"
)

set_target_properties(NEDump PROPERTIES
    MACOSX_BUNDLE YES
    XCODE_ATTRIBUTE_CLANG_ENABLE_MODULES YES
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "NEDump/entitlements"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_LIST_DIR}/NEDump/Info.plist"
    XCODE_ATTRIBUTE_ENABLE_HARDENED_RUNTIME YES
    XCODE_ATTRIBUTE_PROVISIONING_PROFILE_SPECIFIER "NEDump"
    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Developer ID Application"
    XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEV_ID}
    XCODE_ATTRIBUTE_PRODUCT_NAME "NEDump"
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER ${BUNDLE_ID}
)

set_target_properties(${EXT_BUNDLE_ID} PROPERTIES
    MACOSX_BUNDLE YES
    XCODE_PRODUCT_TYPE com.apple.product-type.system-extension
    BUNDLE_EXTENSION systemextension
    XCODE_ATTRIBUTE_ENABLE_HARDENED_RUNTIME YES
    XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS "NEDump/netext/entitlements"
    MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_LIST_DIR}/NEDump/netext/Info.plist"
    XCODE_ATTRIBUTE_MARKETING_VERSION 1.0.0
    XCODE_ATTRIBUTE_CURRENT_PROJECT_VERSION 1.0.0
    XCODE_ATTRIBUTE_PROVISIONING_PROFILE_SPECIFIER "NEDump Network Extension"
    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "Developer ID Application"
    XCODE_ATTRIBUTE_DEVELOPMENT_TEAM ${DEV_ID}
    XCODE_ATTRIBUTE_PRODUCT_NAME "${EXT_BUNDLE_ID}"
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "${EXT_BUNDLE_ID}"
    XCODE_ATTRIBUTE_PRODUCT_BUNDLE_DISPLAY_NAME "${EXT_BUNDLE_ID}"
)

add_custom_command(TARGET NEDump POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory $<TARGET_BUNDLE_DIR:NEDump>/Contents/Library/SystemExtensions/${EXT_BUNDLE_ID}.systemextension
    COMMAND ${CMAKE_COMMAND} -E copy_directory $<TARGET_BUNDLE_DIR:${EXT_BUNDLE_ID}> $<TARGET_BUNDLE_DIR:NEDump>/Contents/Library/SystemExtensions/${EXT_BUNDLE_ID}.systemextension
)
