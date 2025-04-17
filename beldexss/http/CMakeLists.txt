add_library(http STATIC
    http_client.cpp)

target_link_libraries(http
    PRIVATE
    version
    oxen::logging
    PUBLIC
    cpr::cpr
    quic::quic
    )
