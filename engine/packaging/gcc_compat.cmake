# Work around GCC < 15 false-positive -Wstringop-overflow inside libstdc++
# std::vector<unsigned char>::_M_range_insert when compiling read-only
# engine/src/archive/tar_reader.cpp at -O3 with -Werror on Ubuntu 24.04 LTS (GCC 13.3).
function(_mie_pkg_apply_gcc_compat)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS "15.0")
    get_property(_mie_targets DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" PROPERTY BUILDSYSTEM_TARGETS)
    foreach(_tgt IN LISTS _mie_targets)
      get_target_property(_type "${_tgt}" TYPE)
      if(_type STREQUAL "STATIC_LIBRARY" OR _type STREQUAL "SHARED_LIBRARY" OR _type STREQUAL "OBJECT_LIBRARY" OR _type STREQUAL "EXECUTABLE")
        target_compile_options("${_tgt}" PRIVATE -Wno-error=stringop-overflow)
      endif()
    endforeach()
  endif()
endfunction()

cmake_language(DEFER DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" CALL _mie_pkg_apply_gcc_compat)
