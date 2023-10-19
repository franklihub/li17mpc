#pragma once

// context
extern "C" const char* li17_p1_context(const char* private_key, const char* public_key);
extern "C" const char* li17_p2_context(const char* private_key, const char* public_key);
extern "C" const char* li17_p1_public_key(const char* p1_context);
extern "C" const char* li17_p2_public_key(const char* p2_context);

// keygen
extern "C" const char* li17_p1_keygen_send_hash_proof(const char* p1_context);
extern "C" const char* li17_p2_keygen_recv_hash_proof(const char* p2_context, const char* msg);
extern "C" const char* li17_p2_keygen_send_zk_proof(const char* p2_context);
extern "C" const char* li17_p1_keygen_recv_zk_proof(const char* p1_context, const char* msg);
extern "C" const char* li17_p1_keygen_send_zk_proof(const char* p1_context);
extern "C" const char* li17_p2_keygen_recv_zk_proof(const char* p2_context, const char* msg);

// signature
extern "C" const char* li17_p1_signature_send_signature_request(const char* p1_context);
extern "C" const char* li17_p2_signature_recv_signature_request(const char* p2_context, const char* msg);
extern "C" const char* li17_p2_signature_send_signature_partial(const char* p2_context, const char* msg32);
extern "C" const char* li17_p1_signature_recv_signature_partial(const char* p1_context, const char* msg, const char* msg32);

// refresh
extern "C" const char* li17_p1_refresh_send_zk_proof(const char* p1_context);
extern "C" const char* li17_p2_refresh_recv_zk_proof(const char* p2_context, const char* msg);
extern "C" const char* li17_p2_refresh_send_zk_proof(const char* p2_context);
extern "C" const char* li17_p1_refresh_recv_zk_proof(const char* p1_context, const char* msg);