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

include_directories(..)
link_directories(..)
add_executable(kdf_test kdf_test.cc)
target_link_libraries(kdf_test hpke-simdium crypto GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(kdf_test)
