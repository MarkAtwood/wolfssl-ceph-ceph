set(auth_srcs
  AuthClientHandler.cc
  AuthMethodList.cc
  AuthRegistry.cc
  AuthSessionHandler.cc
  Crypto.cc
  KeyRing.cc
  RotatingKeyRing.cc
  cephx/CephxAuthorizeHandler.cc
  cephx/CephxClientHandler.cc
  cephx/CephxProtocol.cc
  cephx/CephxSessionHandler.cc
  none/AuthNoneAuthorizeHandler.cc)

if(HAVE_GSSAPI)
  list(APPEND auth_srcs
    krb/KrbAuthorizeHandler.cpp
    krb/KrbClientHandler.cpp
    krb/KrbProtocol.cpp
    krb/KrbSessionHandler.hpp)
endif()

add_library(common-auth-objs OBJECT ${auth_srcs})
target_include_directories(common-auth-objs PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(common-auth-objs legacy-option-headers)

# Optional: route cephx AES-128-CBC through wolfCrypt directly (FIPS module).
# Guarded so a stock build (WITH_WOLFCRYPT_CEPHX=OFF) is byte-for-byte identical.
if(WITH_WOLFCRYPT_CEPHX)
  # The WITH_WOLFCRYPT_CEPHX define is set globally (top-level
  # add_compile_definitions). PkgConfig::WOLFSSL carries include dirs + link dir
  # + lib; plain signature (matching the call above) still populates
  # INTERFACE_LINK_LIBRARIES so the requirement propagates from this OBJECT
  # library to libceph-common.
  target_link_libraries(common-auth-objs PkgConfig::WOLFSSL)
endif()
