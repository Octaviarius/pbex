project(pbex)

add_library(${PROJECT_NAME} STATIC
    pbex.h
    pbex.c
)

target_link_libraries(${PROJECT_NAME} PUBLIC nanopb)
