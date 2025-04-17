if(NOT TARGET libevent::core)
    add_library(libevent_core INTERFACE)
    pkg_check_modules(LIBEVENT_core libevent_core>=2.1 IMPORTED_TARGET REQUIRED)
    target_link_libraries(libevent_core INTERFACE PkgConfig::LIBEVENT_core)
    add_library(libevent::core ALIAS libevent_core)
endif()

add_library(http STATIC
    http_client.cpp)

target_link_libraries(http
    PRIVATE
    version
    oxen::logging
    libevent::core
    PUBLIC
    cpr::cpr
    quic::quic
    )
