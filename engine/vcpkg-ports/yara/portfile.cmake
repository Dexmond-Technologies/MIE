vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_github(
  OUT_SOURCE_PATH SOURCE_PATH
  REPO VirusTotal/yara
  REF "v${VERSION}"
  # SHA-512 of https://github.com/VirusTotal/yara/archive/v4.5.1.tar.gz (tag v4.5.1 = commit
  # 0e5b6bb9660cba500eb58dbccb027757c82cc4cf), taken on 2026-11-23. vcpkg refuses any other archive.
  SHA512 8bf1df7089f9bc5a448dbae0999e04f4ecdec06b4478e2cb5f42a2a3201b99fce68379e3f8f7c67a9db201205366250d7befe5c38451cced807ed692d436422c
  HEAD_REF master
  PATCHES
    # Module elf request new library tlshc(https://github.com/avast/tlshc), the related upstream PR: https://github.com/VirusTotal/yara/pull/1624.
    Disable-module-elf.patch
)

vcpkg_check_features(OUT_FEATURE_OPTIONS FEATURE_OPTIONS
  FEATURES
    cuckoo    CUCKOO_MODULE
    dotnet    DOTNET_MODULE
)

file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${SOURCE_PATH}")

vcpkg_cmake_configure(
  SOURCE_PATH "${SOURCE_PATH}"
  OPTIONS
      ${FEATURE_OPTIONS}
  OPTIONS_DEBUG 
      -DDISABLE_INSTALL_HEADERS=ON 
      -DDISABLE_INSTALL_TOOLS=ON
)

vcpkg_cmake_install()
vcpkg_cmake_config_fixup(PACKAGE_NAME unofficial-libyara)

set(
    copyright_files
    "${SOURCE_PATH}/COPYING"
    "${SOURCE_PATH}/libyara/modules/pe/authenticode-parser/authenticode.c"
)
if("dotnet" IN_LIST FEATURES)
    vcpkg_install_copyright(
        FILE_LIST
            ${copyright_files}
            "${SOURCE_PATH}/libyara/modules/dotnet/dotnet.c"
        COMMENT "The .NET module is licensed under Apache-2.0; see https://www.apache.org/licenses/LICENSE-2.0."
    )
else()
    vcpkg_install_copyright(FILE_LIST ${copyright_files})
endif()
