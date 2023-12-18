
add_library(logging STATIC
    beldex_logger.cpp
)

target_link_libraries(logging PUBLIC oxen::logging)
