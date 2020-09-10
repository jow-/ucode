cmake_minimum_required(VERSION 2.6)
include(CheckFunctionExists)

PROJECT(utpl C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-error=unused-variable -ffunction-sections -D_GNU_SOURCE)

OPTION(FS_SUPPORT "Filesystem plugin support" ON)
OPTION(UBUS_SUPPORT "Ubus plugin support" ON)

SET(LIB_SEARCH_PATH "/usr/lib/utpl/*.so:/usr/share/utpl/*.utpl:./*.so:./*.utpl" CACHE STRING "Default library search path")
ADD_DEFINITIONS(-DLIB_SEARCH_PATH="${LIB_SEARCH_PATH}")

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

SET_PROPERTY(DIRECTORY APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES "lemon;parser.h;parser.out")
SET_SOURCE_FILES_PROPERTIES("parser.c" PROPERTIES GENERATED TRUE COMPILE_FLAGS -Wno-error=unused-but-set-variable)
ADD_EXECUTABLE(utpl main.c ast.c lexer.c parser.c eval.c lib.c)
TARGET_LINK_LIBRARIES(utpl ${json})

CHECK_FUNCTION_EXISTS(ceil CEIL_FUNCTION_EXISTS)
IF (NOT CEIL_FUNCTION_EXISTS)
  TARGET_LINK_LIBRARIES(utpl m)
ENDIF()

CHECK_FUNCTION_EXISTS(dlopen DLOPEN_FUNCTION_EXISTS)
IF (NOT DLOPEN_FUNCTION_EXISTS)
  TARGET_LINK_LIBRARIES(utpl dl)
ENDIF()

SET(LIBRARIES "")

IF(FS_SUPPORT)
  SET(LIBRARIES ${LIBRARIES} fs_lib)
  ADD_LIBRARY(fs_lib MODULE lib/fs.c)
  SET_TARGET_PROPERTIES(fs_lib PROPERTIES OUTPUT_NAME lib/fs PREFIX "")
ENDIF()

IF(UBUS_SUPPORT)
  SET(LIBRARIES ${LIBRARIES} ubus_lib)
  ADD_LIBRARY(ubus_lib MODULE lib/ubus.c)
  SET_TARGET_PROPERTIES(ubus_lib PROPERTIES OUTPUT_NAME lib/ubus PREFIX "")
  TARGET_LINK_LIBRARIES(ubus_lib ubus blobmsg_json)
ENDIF()

INSTALL(TARGETS utpl RUNTIME DESTINATION bin)
