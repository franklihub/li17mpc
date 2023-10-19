#include "gmp.h"
#include "li17.h"
#include "proof.h"
#include "paillier.h"
#include "secp256k1.h"
#include "json/json.h"

#include <string>
#include <vector>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

extern "C" const char* li17_p1_context(const char* private_key_string)
{
    string result;

    string private_key;

    if (private_key_string != nullptr) private_key = private_key_string;
    if (private_key.empty()) private_key = secp256k1_private_key();

    string zk_proof    = zk_prove(private_key);
    string hash_proof  = hash_prove(zk_proof);

    string k1          = secp256k1_private_key();
    string k1_zk_proof = zk_prove(k1);

    json context = json::object
    {
        {"k1",          k1},
        {"k1_zk_proof", json::parse(k1_zk_proof)},
        {"private_key", private_key},
        {"zk_proof",    json::parse(zk_proof)},
        {"hash_proof",  json::parse(hash_proof)},
        {"paillier",    json::parse(paillier_decrypt_key())},
        {"paillier_zk", json::parse(paillier_decrypt_key())},
    };

    result = context.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p2_context(const char* private_key_string, const char* public_key_string)
{
    string result;

    string public_key;
    string private_key;

    if (public_key_string  != nullptr) public_key  = public_key_string;
    if (private_key_string != nullptr) private_key = private_key_string;
    if (private_key.empty()) private_key = secp256k1_private_key();

    string zk_proof = zk_prove(private_key);

    string k2 = secp256k1_private_key();
    string k2_zk_proof = zk_prove(k2);

    json context = json::object
    {
        {"k2",          k2},
        {"k2_zk_proof", json::parse(k2_zk_proof)},
        {"public_key",  public_key},
        {"private_key", private_key},
        {"zk_proof",    json::parse(zk_proof)},
    };

    if (context["public_key"].to_string().empty()) context.erase("public_key");
    
    result = context.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p1_public_key(const char* p1_context)
{
    string result;
    
    json   context    = json::parse(p1_context);
    string public_key = context["public_key"].to_string();

    result = public_key;

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p2_public_key(const char* p2_context)
{
    string result;

    json   context    = json::parse(p2_context);
    string public_key = context["public_key"].to_string();

    result = public_key;

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p1_keygen_send_hash_proof(const char* p1_context)
{
    string result;

    json   context     = json::parse(p1_context);
    string private_key = context["private_key"].to_string();

    json hash_proof_hash = context["hash_proof"];
    hash_proof_hash.erase("random");

    result = hash_proof_hash.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p2_keygen_recv_hash_proof(const char* p2_context, const char* msg)
{
    string result;

    json hash_proof = json::parse(msg);
    json context    = json::parse(p2_context);

    context.insert("hash_proof", hash_proof);

    result = context.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p2_keygen_send_zk_proof(const char* p2_context)
{
    string result;

    json context = json::parse(p2_context);

    result = context["zk_proof"].to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p1_keygen_recv_zk_proof(const char* p1_context, const char* msg)
{
    string result;

    json   zk_proof    = json::parse(msg);
    json   context     = json::parse(p1_context);
    string private_key = context["private_key"].to_string();

    if (zk_verify(zk_proof.to_string()))
    {
        string public_key = secp256k1_public_key_mul(zk_proof["public_key"].to_string(), private_key);
        context.insert("public_key", public_key);
    }

    result = context.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p1_keygen_send_zk_proof(const char* p1_context)
{
    string result;

    json   context     = json::parse(p1_context);
    string private_key = context["private_key"].to_string();

    json   zk_proof   = context["zk_proof"];
    json   hash_proof = context["hash_proof"];

    hash_proof.erase("hash");

    json msg = json::object
    {
        {"hash_proof", hash_proof},
        {"zk_proof",   zk_proof},
    };

    result = msg.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p2_keygen_recv_zk_proof(const char* p2_context, const char* msg)
{
    string result;

    json   proof       = json::parse(msg);
    json   context     = json::parse(p2_context);
    string private_key = context["private_key"].to_string();

    json   zk_proof    = proof["zk_proof"];
    json   hash_proof  = proof["hash_proof"];

    hash_proof.insert("hash", context["hash_proof"]["hash"]);
    context.erase("hash_proof");

    string zk_proof_string   = zk_proof.to_string();
    string hash_proof_string = hash_proof.to_string();

    if (hash_verify(zk_proof_string, hash_proof_string) && zk_verify(zk_proof_string))
    {
        string public_key = secp256k1_public_key_mul(zk_proof["public_key"].to_string(), private_key);
        context.insert("public_key", public_key);
    }

    result = context.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p1_signature_send_signature_request(const char* p1_context)
{
    string result;

    json   context = json::parse(p1_context);
    string private_key = context["private_key"].to_string();
    string decrypt_key = context["paillier"].to_string();
    string paillier_zk = context["paillier_zk"].to_string();

    string encrypt_key = paillier_encrypt_key(decrypt_key);
    string ckey_random = paillier_random(encrypt_key);
    string ckey        = paillier_encrypt(encrypt_key, private_key, ckey_random);

    json msg = json::object
    {
        {"ckey",                    ckey},
        {"paillier",                json::parse(encrypt_key)},
        {"k1_zk_proof",             context["k1_zk_proof"]},
        {"zk_paillier_n_proof",     json::parse(zk_paillier_n_prove(decrypt_key))},
        {"zk_paillier_range_proof", json::parse(zk_paillier_range_prove(paillier_zk, decrypt_key, private_key, ckey, ckey_random))},
    };

    result = msg.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p2_signature_recv_signature_request(const char* p2_context, const char* msg)
{
    string result;

    json request = json::parse(msg);
    json context = json::parse(p2_context);

    json   paillier                = request["paillier"];
    json   k1_zk_proof             = request["k1_zk_proof"];
    string zk_paillier_n_proof     = request["zk_paillier_n_proof"].to_string();
    string zk_paillier_range_proof = request["zk_paillier_range_proof"].to_string();
    
    string encrypt_key = paillier.to_string();

    if (zk_verify(k1_zk_proof.to_string()) && zk_paillier_n_verify(encrypt_key, zk_paillier_n_proof) && zk_paillier_range_verify(zk_paillier_range_proof))
    {
        context.insert("ckey", request["ckey"]);
        context.insert("paillier", request["paillier"]);
        context.insert("k1_zk_proof", k1_zk_proof);
    }

    result = context.to_string();
    
    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p2_signature_send_signature_partial(const char* p2_context, const char* msg32)
{
    string result;

    json   context                 = json::parse(p2_context);
    string private_key2            = context["private_key"].to_string();
    string public_key              = context["public_key"].to_string();
    string ckey                    = context["ckey"].to_string();
    string encrypt_key             = context["paillier"].to_string();
    json   k1_zk_proof             = context["k1_zk_proof"];
    string zk_paillier_n_proof     = context["zk_paillier_n_proof"].to_string();
    string zk_paillier_range_proof = context["zk_paillier_range_proof"].to_string();
    
    string k2                      = secp256k1_private_key();
    string r                       = secp256k1_public_key_mul(k1_zk_proof["public_key"].to_string(), k2);
    string signature_partial       = paillier_signature_partial(encrypt_key, r, k2, ckey, private_key2, msg32);

    json msg = json::object
    {
        {"signature_partial", signature_partial},
        {"k2_zk_proof",       json::parse(zk_prove(k2))},
        {"public_key",        public_key},
    };

    result = msg.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p1_signature_recv_signature_partial(const char* p1_context, const char* msg, const char* msg32)
{
    string result;

    json   peer              = json::parse(msg);
    json   context           = json::parse(p1_context);
    string signature_partial = peer["signature_partial"].to_string();
    string public_key        = peer["public_key"].to_string();
    string decrypt_key       = context["paillier"].to_string();
    string k1                = context["k1"].to_string();
    json   k2_zk_proof       = peer["k2_zk_proof"];

    if (zk_verify(k2_zk_proof.to_string()))
    {
        string r = secp256k1_public_key_mul(k2_zk_proof["public_key"].to_string(), k1);
        string signature = paillier_signature(decrypt_key, r, k1, signature_partial);

        if (secp256k1_verify_signature(public_key, signature, msg32))
        {
            for (size_t i = 0; i < 4; ++i)
            {
                signature = signature.substr(0, signature.size() - 1) + to_string(i);
                string recover = secp256k1_recover_public_key(signature, msg32);
                if (recover == public_key)
                {
                    result = signature;
                    break;
                }
            }
        }
    }

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p1_refresh_send_zk_proof(const char* p1_context)
{
    string result;

    json context     = json::parse(p1_context);
    json k1_zk_proof = context["k1_zk_proof"];

    json msg = json::object
    {
        {"k1_zk_proof", k1_zk_proof},
    };

    result = msg.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p2_refresh_recv_zk_proof(const char* p2_context, const char* msg)
{
    string result;

    json   peer        = json::parse(msg);
    json   context     = json::parse(p2_context);
    string private_key = context["private_key"].to_string();
    string k2          = context["k2"].to_string();
    json   k1_zk_proof = peer["k1_zk_proof"];

    if (zk_verify(k1_zk_proof.to_string()))
    {
        string r            = secp256k1_public_key_mul(k1_zk_proof["public_key"].to_string(), k2);
        string random       = mpz_mod(sha256(r), secp256k1_order());
        string private_key1 = secp256k1_private_key_mul(private_key, random);

        result = private_key1;
    }

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p2_refresh_send_zk_proof(const char* p2_context)
{
    string result;

    json context     = json::parse(p2_context);
    json k2_zk_proof = context["k2_zk_proof"];

    json msg = json::object
    {
        {"k2_zk_proof", k2_zk_proof},
    };

    result = msg.to_string();

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}

extern "C" const char* li17_p1_refresh_recv_zk_proof(const char* p1_context, const char* msg)
{
    string result;

    json   peer        = json::parse(msg);
    json   context     = json::parse(p1_context);
    string private_key = context["private_key"].to_string();
    string k1          = context["k1"].to_string();
    json   k2_zk_proof = peer["k2_zk_proof"];

    if (zk_verify(k2_zk_proof.to_string()))
    {
        string r            = secp256k1_public_key_mul(k2_zk_proof["public_key"].to_string(), k1);
        string random       = mpz_mod(sha256(r), secp256k1_order());
        string random_inv   = mpz_mod_inv(random, secp256k1_order());
        string private_key2 = secp256k1_private_key_mul(private_key, random_inv);

        result = private_key2;
    }

    if (result.empty()) return nullptr;
    size_t size = result.size() + 1;
    char*  data = (char*)malloc(size);
    memset(data, 0, size);
    memcpy(data, result.data(), result.size());
    return data;
}
