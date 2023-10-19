cmake_minimum_required(VERSION 3.13.0)

project (li17_core)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -sWASM={0,1} -sSINGLE_FILE -sEXPORTED_RUNTIME_METHODS=stackAlloc,UTF8ToString,lengthBytesUTF8,stringToUTF8")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -sEXPORTED_FUNCTIONS=_li17_p1_context,_li17_p2_context,_li17_p1_public_key,_li17_p2_public_key,_li17_p1_keygen_send_hash_proof,_li17_p2_keygen_recv_hash_proof,_li17_p2_keygen_send_zk_proof,_li17_p1_keygen_recv_zk_proof,_li17_p1_keygen_send_zk_proof,_li17_p2_keygen_recv_zk_proof,_li17_p1_signature_send_signature_request,_li17_p2_signature_recv_signature_request,_li17_p2_signature_send_signature_partial,_li17_p1_signature_recv_signature_partial,_li17_p1_refresh_send_zk_proof,_li17_p2_refresh_recv_zk_proof,_li17_p2_refresh_send_zk_proof,_li17_p1_refresh_recv_zk_proof")

file(GLOB_RECURSE SOURCES "*.h" "*.cpp")

add_executable(li17_core ${SOURCES})
