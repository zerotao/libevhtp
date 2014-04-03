#- Add sources for a target
#
#  ADD_TARGET_INCLUDE_DIRS(<target> <path> [<path2> ...])
#
function(add_target_include_dirs target)
  # define the <target>_INCLUDE_DIRS properties if necessary
  get_property(prop_defined GLOBAL PROPERTY ${target}_INCLUDE_DIRS DEFINED)
  if(NOT prop_defined)
    define_property(GLOBAL PROPERTY ${target}_INCLUDE_DIRS
      BRIEF_DOCS "include dirs for the ${target} target"
      FULL_DOCS "List of include dirs for the ${target} target")
  endif()

  set(PATHS)
  foreach(path IN LISTS ARGN)
    list(APPEND PATHS "${path}")
  endforeach()

  set_property(GLOBAL APPEND PROPERTY "${target}_INCLUDE_DIRS" "${PATHS}")
endfunction()


#
#  ADD_TARGET_SOURCES(<target> <source1> [<source2> ...])
#
function(add_target_sources target)
  # define the <target>_SRCS properties if necessary
  get_property(prop_defined GLOBAL PROPERTY ${target}_SRCS DEFINED)
  if(NOT prop_defined)
    define_property(GLOBAL PROPERTY ${target}_SRCS
      BRIEF_DOCS "Sources for the ${target} target"
      FULL_DOCS "List of source files for the ${target} target")
  endif()


  # create list of sources (absolute paths)
  set(SRCS)
  foreach(src IN LISTS ARGN)
    if(NOT IS_ABSOLUTE "${src}")
      get_filename_component(src "${src}" ABSOLUTE)
    endif()
    list(APPEND SRCS "${src}")
  endforeach()

  # append to global property
  set_property(GLOBAL APPEND PROPERTY "${target}_SRCS" "${SRCS}")

  # append to the global property
  add_target_include_dirs(${target} ${CMAKE_CURRENT_SOURCE_DIR})
  add_target_include_dirs(${target} ${CMAKE_CURRENT_BINARY_DIR})
endfunction()

