enable_language(CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest
  GIT_TAG v1.16.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
include(GoogleTest)

include_directories(..)

add_executable(kdf_ossl kdf_test.cc ../kdf_ossl.c ../kdf.c ../types.c)
target_include_directories(kdf_ossl PRIVATE ../third_party/ossl/include)
target_link_libraries(kdf_ossl PRIVATE crypto_ossl GTest::gtest_main)
target_link_directories(kdf_ossl PRIVATE ../third_party/ossl/lib64)
gtest_discover_tests(kdf_ossl)

add_executable(kdf_bssl kdf_test.cc ../kdf_bssl.c ../kdf.c ../types.c)
target_compile_definitions(kdf_bssl PRIVATE BORINGSSL_PREFIX=BSSL_)
target_include_directories(kdf_bssl PRIVATE ../third_party/bssl/include)
target_link_libraries(kdf_bssl PRIVATE crypto_bssl GTest::gtest_main)
target_link_directories(kdf_bssl PRIVATE ../third_party/bssl/lib64)
gtest_discover_tests(kdf_bssl)

