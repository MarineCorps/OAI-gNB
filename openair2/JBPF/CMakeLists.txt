# JBPF Hook Framework 빌드 설정

# Codelet 빌드 (JBPF_HOOK이 활성화된 경우에만)
if(JBPF_HOOK)
    message(STATUS "Building JBPF codelets...")
    add_subdirectory(codelets)
endif()
