CMAKE_MINIMUM_REQUIRED(VERSION 2.7)

set (PROJECT_NAME etw)
PROJECT(${PROJECT_NAME})

file(GLOB HDRS "*.h*")
file(GLOB SRCS "*.cpp" )

include_directories(../include )

add_library (${PROJECT_NAME} ${SRCS} ${HDRS})
