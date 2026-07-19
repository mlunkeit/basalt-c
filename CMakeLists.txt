cmake_minimum_required(VERSION 4.3)
project(basalt C)

set(CMAKE_C_STANDARD 23)

add_library(basalt STATIC library.c)
