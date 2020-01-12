/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2019  GreaterFire, ffftwo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include <cstdlib>
#include <sstream>
#include <stdexcept>
#include <boost/property_tree/json_parser.hpp>
#include <openssl/sha.h>
using namespace std;
using namespace boost::property_tree;

void Config::load() {
    populate();
}

void Config::populate(const std::string &JSON) {
    istringstream s(JSON);
    ptree tree;
    read_json(s, tree);
    populate();
}

void Config::populate() {
        run_type = CLIENT;
    local_addr = "127.0.0.1";
    local_port = uint16_t(1080);
    //remote_addr = "youHost.com";//fill your host name or ip
    remote_port = uint16_t(22334);
    target_addr = "";
    target_port = 0;
    map<string, string>().swap(password);
//    for (auto& item: tree.get_child("password")) {
        //string p = "your_password";//fill your password
        password[SHA224(p)] = p;
//    }
    udp_timeout = 60;
    log_level = static_cast<Log::Level>(1);
    ssl.verify = true;
    ssl.verify_hostname = true;
    ssl.cert = "/data/user/0/com.ycf.igniter/cache/cacert.pem";
    ssl.key = "";
    ssl.key_password = "";
	//ssl.cipher = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:RSA-AES128-GCM-SHA256:RSA-AES256-GCM-SHA384:RSA-AES128-SHA:RSA-AES256-SHA:RSA-3DES-EDE-SHA";//choose your cipher best for mobile
    ssl.cipher_tls13 = "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384";
    ssl.prefer_server_cipher = true;
    ssl.sni = "";
    ssl.alpn = "";
//    for (auto& item: tree.get_child("ssl.alpn")) {
        string proto = "h2";
        ssl.alpn += (char)((unsigned char)(proto.length()));
        ssl.alpn += proto;
//    }
    ssl.reuse_session = true;
    ssl.session_ticket = false;
    ssl.session_timeout = long(600);
    ssl.plain_http_response = "";
    ssl.curves = "";
    ssl.dhparam = "";
    tcp.prefer_ipv4 = true;
    tcp.no_delay = true;
    tcp.keep_alive = true;
    tcp.reuse_port = false;
    tcp.fast_open = true;
    tcp.fast_open_qlen = 20;
    mysql.enabled = false;
    mysql.server_addr = "127.0.0.1";
    mysql.server_port = uint16_t(3306);
    mysql.database = "trojan";
    mysql.username = "trojan";
    mysql.password = "";
}

bool Config::sip003() {
    char *JSON = getenv("SS_PLUGIN_OPTIONS");
    if (JSON == NULL) {
        return false;
    }
    populate(JSON);
    switch (run_type) {
        case SERVER:
            local_addr = getenv("SS_REMOTE_HOST");
            local_port = atoi(getenv("SS_REMOTE_PORT"));
            break;
        case CLIENT:
        case NAT:
            throw runtime_error("SIP003 with wrong run_type");
            break;
        case FORWARD:
            remote_addr = getenv("SS_REMOTE_HOST");
            remote_port = atoi(getenv("SS_REMOTE_PORT"));
            local_addr = getenv("SS_LOCAL_HOST");
            local_port = atoi(getenv("SS_LOCAL_PORT"));
            break;
    }
    return true;
}

string Config::SHA224(const string &message) {
    uint8_t digest[SHA224_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA224_Init(&ctx);
    SHA224_Update(&ctx, message.c_str(), message.length());
    SHA224_Final(digest, &ctx);
    char mdString[(SHA224_DIGEST_LENGTH << 1) + 1];
    for (int i = 0; i < SHA224_DIGEST_LENGTH; ++i) {
        sprintf(mdString + (i << 1), "%02x", (unsigned int)digest[i]);
    }
    return string(mdString);
}
