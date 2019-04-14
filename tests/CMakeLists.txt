CMAKE_MINIMUM_REQUIRED(VERSION 2.7)

set (PROJECT_NAME libetw-tests)
PROJECT(${PROJECT_NAME})

file(GLOB HDRS "../*.h*" )
file(GLOB SRCS "*.cpp")

include_directories(.. ${GTEST_DIR}/include )


add_executable (${PROJECT_NAME} ${SRCS} ${HDRS})

FIND_LIBRARY(LIBGTEST gtest HINT "$ENV{GTEST_DIR}/lib" )

TARGET_LINK_LIBRARIES(${PROJECT_NAME} etw ${LIBGTEST} )
