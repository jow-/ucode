cmake_minimum_required(VERSION 2.6)
include(CheckFunctionExists)

PROJECT(utpl C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-error=unused-variable -ffunction-sections -D_GNU_SOURCE)

IF(NOT APPLE)
  SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "-Wl,--gc-sections")
ENDIF()

find_library(json NAMES json-c json)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3 -O0)
ELSE()
  ADD_DEFINITIONS(-DNDEBUG)
ENDIF()

INCLUDE(FindPkgConfig)
PKG_CHECK_MODULES(JSONC json-c json)
IF(JSONC_FOUND)
  ADD_DEFINITIONS(-DJSONC)
  INCLUDE_DIRECTORIES(${JSONC_INCLUDE_DIRS})
ENDIF()

ADD_CUSTOM_COMMAND(
  OUTPUT contrib/lemon
  DEPENDS contrib/lemon.c contrib/lempar.c
  COMMAND gcc -o contrib/lemon contrib/lemon.c
  COMMENT "Generating lemon parser generator"
)

ADD_CUSTOM_COMMAND(
  OUTPUT parser.c
  DEPENDS parser.y contrib/lemon
  COMMAND ./contrib/lemon parser.y
  COMMENT "Generating parser.c"
)

FIND_PATH(ubox_include_dir libubox/list.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})

SET_PROPERTY(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "lemon;parser.h;parser.out")
SET_SOURCE_FILES_PROPERTIES("parser.c" PROPERTIES GENERATED TRUE COMPILE_FLAGS -Wno-error=unused-but-set-variable)
ADD_EXECUTABLE(utpl main.c ast.c lexer.c parser.c eval.c lib.c)
TARGET_LINK_LIBRARIES(utpl ubox ${json})

CHECK_FUNCTION_EXISTS(ceil CEIL_FUNCTION_EXISTS)
IF (NOT CEIL_FUNCTION_EXISTS)
  TARGET_LINK_LIBRARIES(utpl m)
ENDIF()

INSTALL(TARGETS utpl RUNTIME DESTINATION bin)
