cmake_minimum_required(VERSION 3.20)

project(pbex_test LANGUAGES C)

add_executable(${PROJECT_NAME}
    pbex_test.pb.h pbex_test.pb.c
    pbex_test.c
    ../pbex.h ../pbex.c
    ../lib/nanopb/pb.h
    ../lib/nanopb/pb_common.h ../lib/nanopb/pb_common.c
    ../lib/nanopb/pb_decode.h ../lib/nanopb/pb_decode.c
    ../lib/nanopb/pb_encode.h ../lib/nanopb/pb_encode.c
)

target_include_directories(${PROJECT_NAME} PUBLIC
    ../lib/nanopb/
    ../
)
