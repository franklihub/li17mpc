function li17_p1_context(private_key, public_key)
{
    var v1 = private_key;
    var v2 = public_key;

    var arg1 = null;
    if (v1)
    {
        var len1 = lengthBytesUTF8(v1) * 4 + 1;
        arg1 = stackAlloc(len1);
        stringToUTF8(v1, arg1, len1);
    }

    var arg2 = null;
    if (v2)
    {
        var len2 = lengthBytesUTF8(v2) * 4 + 1;
        arg2 = stackAlloc(len2);
        stringToUTF8(v2, arg2, len2);
    }

    return UTF8ToString(_li17_p1_context(arg1, arg2));
}

function li17_p1_public_key(p1_context)
{
    var v1 = p1_context;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    return UTF8ToString(_li17_p1_public_key(arg1));
}

function li17_p1_keygen_send_hash_proof(p1_context)
{
    var v1 = p1_context;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    return UTF8ToString(_li17_p1_keygen_send_hash_proof(arg1));
}

function li17_p1_keygen_recv_zk_proof(p1_context, msg)
{
    var v1 = p1_context;
    var v2 = msg;

    var len1 = lengthBytesUTF8(v1)* 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    var len2 = lengthBytesUTF8(v2) * 4 + 1;
    var arg2 = stackAlloc(len2);
    stringToUTF8(v2, arg2, len2);

    return UTF8ToString(_li17_p1_keygen_recv_zk_proof(arg1, arg2));
}

function li17_p1_keygen_send_zk_proof(p1_context)
{
    var v1 = p1_context;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    return UTF8ToString(_li17_p1_keygen_send_zk_proof(arg1));
}

function li17_p1_signature_send_signature_request(p1_context)
{
    var v1 = p1_context;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    return UTF8ToString(_li17_p1_signature_send_signature_request(arg1));
}

function li17_p1_signature_recv_signature_partial(p1_context, msg, msg32)
{
    var v1 = p1_context;
    var v2 = msg;
    var v3 = msg32;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    var len2 = lengthBytesUTF8(v2) * 4 + 1;
    var arg2 = stackAlloc(len2);
    stringToUTF8(v2, arg2, len2);

    var len3 = lengthBytesUTF8(v3) * 4 + 1;
    var arg3 = stackAlloc(len3);
    stringToUTF8(v3, arg3, len3);

    return UTF8ToString(_li17_p1_signature_recv_signature_partial(arg1, arg2, arg3));
}

function li17_p1_refresh_send_zk_proof(p1_context)
{
    var v1 = p1_context;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    return UTF8ToString(_li17_p1_refresh_send_zk_proof(arg1));
}

function li17_p1_refresh_recv_zk_proof(p1_context, msg)
{
    var v1 = p1_context;
    var v2 = msg;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    var len2 = lengthBytesUTF8(v2) * 4 + 1;
    var arg2 = stackAlloc(len2);
    stringToUTF8(v2, arg2, len2);

    return UTF8ToString(_li17_p1_refresh_recv_zk_proof(arg1, arg2));
}

function li17_p2_context(private_key, public_key)
{
    var v1 = private_key;
    var v2 = public_key;

    var arg1 = null;
    if (v1)
    {
        var len1 = lengthBytesUTF8(v1) * 4 + 1;
        arg1 = stackAlloc(len1);
        stringToUTF8(v1, arg1, len1);
    }

    var arg2 = null;
    if (v2)
    {
        var len2 = lengthBytesUTF8(v2) * 4 + 1;
        arg2 = stackAlloc(len2);
        stringToUTF8(v2, arg2, len2);
    }

    return UTF8ToString(_li17_p2_context(arg1, arg2));
}

function li17_p2_public_key(p2_context)
{
    var v1 = p2_context;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    var check = UTF8ToString(arg1);

    return UTF8ToString(_li17_p2_public_key(arg1));
}

function li17_p2_keygen_recv_hash_proof(p2_context, msg)
{
    var v1 = p2_context;
    var v2 = msg;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    var len2 = lengthBytesUTF8(v2) * 4 + 1;
    var arg2 = stackAlloc(len2);
    stringToUTF8(v2, arg2, len2);

    return UTF8ToString(_li17_p2_keygen_recv_hash_proof(arg1, arg2));
}

function li17_p2_keygen_send_zk_proof(p2_context)
{
    var v1 = p2_context;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    return UTF8ToString(_li17_p2_keygen_send_zk_proof(arg1));
}

function li17_p2_keygen_recv_zk_proof(p2_context, msg)
{
    var v1 = p2_context;
    var v2 = msg;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    var len2 = lengthBytesUTF8(v2) * 4 + 1;
    var arg2 = stackAlloc(len2);
    stringToUTF8(v2, arg2, len2);

    return UTF8ToString(_li17_p2_keygen_recv_zk_proof(arg1, arg2));
}

function li17_p2_signature_recv_signature_request(p2_context, msg)
{
    var v1 = p2_context;
    var v2 = msg;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    var len2 = lengthBytesUTF8(v2) * 4 + 1;
    var arg2 = stackAlloc(len2);
    stringToUTF8(v2, arg2, len2);

    return UTF8ToString(_li17_p2_signature_recv_signature_request(arg1, arg2));
}

function li17_p2_signature_send_signature_partial(p2_context, msg32)
{
    var v1 = p2_context;
    var v2 = msg32;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    var len2 = lengthBytesUTF8(v2) * 4 + 1;
    var arg2 = stackAlloc(len2);
    stringToUTF8(v2, arg2, len2);

    return UTF8ToString(_li17_p2_signature_send_signature_partial(arg1, arg2));
}

function li17_p2_refresh_send_zk_proof(p2_context)
{
    var v1 = p2_context;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    return UTF8ToString(_li17_p2_refresh_send_zk_proof(arg1));
}

function li17_p2_refresh_recv_zk_proof(p2_context, msg)
{
    var v1 = p2_context;
    var v2 = msg;

    var len1 = lengthBytesUTF8(v1) * 4 + 1;
    var arg1 = stackAlloc(len1);
    stringToUTF8(v1, arg1, len1);

    var len2 = lengthBytesUTF8(v2) * 4 + 1;
    var arg2 = stackAlloc(len2);
    stringToUTF8(v2, arg2, len2);

    return UTF8ToString(_li17_p2_refresh_recv_zk_proof(arg1, arg2));
}
