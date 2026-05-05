# PamAuth - requires PAM

if(NOT PAM_FOUND)
    message(STATUS "PamAuth requires PAM, skipping")
    return()
endif()

add_3proxy_plugin(PamAuth
    SOURCES pamauth.c
)

if(3PROXY_STATIC_LINK)
    set(_saved_cmake_find_library_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    find_library(_pam_static_lib pam)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_saved_cmake_find_library_suffixes})
    if(_pam_static_lib)
        target_link_libraries(PamAuth PRIVATE -Wl,-Bstatic ${_pam_static_lib} -Wl,-Bdynamic)
        message(STATUS "PamAuth: static PAM")
    else()
        message(WARNING "3PROXY_STATIC_LINK is ON but static PAM not found, using dynamic")
        target_link_libraries(PamAuth PRIVATE PAM::PAM)
    endif()
else()
    target_link_libraries(PamAuth PRIVATE PAM::PAM)
endif()
