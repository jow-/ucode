FILE(GLOB examples "*.c")
FOREACH(example ${examples})
  GET_FILENAME_COMPONENT(example ${example} NAME_WE)
  SET(CLI_SOURCES main.c)
  ADD_EXECUTABLE(${example} ${example}.c)
  TARGET_LINK_LIBRARIES(${example} libucode ${json})
ENDFOREACH(example)
