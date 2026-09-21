cmake_minimum_required(VERSION 3.15)
project(peparser C)

set(CMAKE_C_STANDARD 11)

file(GLOB SOURCES "PEparser/*.c")
file(GLOB HEADERS "PEparser/*.h")

add_executable(peparser ${SOURCES} ${HEADERS})
