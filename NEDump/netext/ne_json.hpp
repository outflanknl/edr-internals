#pragma once

#include <bsm/libbsm.h>
#include <libproc.h>
#include <pwd.h>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

constexpr std::array<const char*, 5> socket_type_names = {
    "SOCK_STREAM",
    "SOCK_DGRAM",
    "SOCK_RAW",
    "SOCK_RDM",
    "SOCK_SEQPACKET"
};

constexpr std::array<const char*, 35> socket_family_names = {
    "PF_UNSPEC",
    "PF_UNIX/PF_LOCAL",
    "PF_INET",
    "PF_IMPLINK",
    "PF_PUP",
    "PF_CHAOS",
    "PF_NS",
    "PF_ISO/PF_OSI",
    "PF_ECMA",
    "PF_DATAKIT",
    "PF_CCITT",
    "PF_SNA",
    "PF_DECnet",
    "PF_DLI",
    "PF_LAT",
    "PF_HYLINK",
    "PF_APPLETALK",
    "PF_ROUTE",
    "PF_LINK",
    "PF_XTP",
    "PF_COIP",
    "PF_CNT",
    "PF_RTIP",
    "PF_IPX",
    "PF_SIP",
    "PF_PIP",
    nullptr,
    "PF_NDRV",
    "PF_ISDN",
    "PF_KEY",
    "PF_INET6",
    "PF_NATM",
    "PF_SYSTEM",
    "PF_NETBIOS",
    "PF_PPP"
};

constexpr std::array<const char*, 60> socket_protocol_names = {
    "IPPROTO_IP",
    "IPPROTO_ICMP",
    "IPPROTO_IGMP",
    "IPPROTO_GGP",
    "IPPROTO_IPV4",
    nullptr,
    "IPPROTO_TCP",
    "IPPROTO_ST",
    "IPPROTO_EGP",
    "IPPROTO_PIGP",
    "IPPROTO_RCCMON",
    "IPPROTO_NVPII",
    "IPPROTO_PUP",
    "IPPROTO_ARGUS",
    "IPPROTO_EMCON",
    "IPPROTO_XNET",
    "IPPROTO_CHAOS",
    "IPPROTO_UDP",
    "IPPROTO_MUX",
    "IPPROTO_MEAS",
    "IPPROTO_HMP",
    "IPPROTO_PRM",
    "IPPROTO_IDP",
    "IPPROTO_TRUNK1",
    "IPPROTO_TRUNK2",
    "IPPROTO_LEAF1",
    "IPPROTO_LEAF2",
    "IPPROTO_RDP",
    "IPPROTO_IRTP",
    "IPPROTO_TP",
    "IPPROTO_BLT",
    "IPPROTO_NSP",
    "IPPROTO_INP",
    "IPPROTO_SEP",
    "IPPROTO_3PC",
    "IPPROTO_IDPR",
    "IPPROTO_XTP",
    "IPPROTO_DDP",
    "IPPROTO_CMTP",
    "IPPROTO_TPXX",
    "IPPROTO_IL",
    "IPPROTO_IPV6",
    "IPPROTO_SDRP",
    "IPPROTO_ROUTING",
    "IPPROTO_FRAGMENT",
    "IPPROTO_IDRP",
    "IPPROTO_RSVP",
    "IPPROTO_GRE",
    "IPPROTO_MHRP",
    "IPPROTO_BHA",
    "IPPROTO_ESP",
    "IPPROTO_AH",
    "IPPROTO_INLSP",
    "IPPROTO_SWIPE",
    "IPPROTO_NHRP",
    nullptr,
    nullptr,
    nullptr,
    "IPPROTO_ICMPV6",
    "IPPROTO_NONE"
};

constexpr std::array<const char*, 3> traffic_direction_names = {
    "NETrafficDirectionAny",
    "NETrafficDirectionInbound",
    "NETrafficDirectionOutbound"
};

void to_json(json& j, const NSString* s) {
    const char* utf8String = s.UTF8String;
    if (utf8String == nullptr) {
        j = nullptr;
        return;
    }

    j = json{ utf8String };
}

void to_json(json& j, const NSURL* u) {
    if (u == nullptr) {
        j = nullptr;
        return;
    }

    const char* utf8String = u.absoluteString.UTF8String;
    if (utf8String == nullptr) {
        j = nullptr;
        return;
    }

    j = json{ utf8String };
}

void to_json(json& j, const NWHostEndpoint* e) {
    if (e == nullptr) {
        j = nullptr;
        return;
    }

    const char* hostname = e.hostname.UTF8String;
    const char* port = e.port.UTF8String;
    if (hostname == nullptr || port == nullptr) {
        j = nullptr;
        return;
    }

    j = json{
        { "hostname", hostname },
        { "port", port }
    };
}

void to_json(json& j, const audit_token_t* t) {
    if (t == nullptr) {
        j = nullptr;
        return;
    }

    pid_t pid = audit_token_to_pid(*t);
    uid_t uid = audit_token_to_euid(*t);

    char path[PROC_PIDPATHINFO_MAXSIZE];
    proc_pidpath(pid, path, PROC_PIDPATHINFO_MAXSIZE);

    struct passwd* pwd = getpwuid(uid);
    int pwd_name_len = 0;
    char pwd_name[256] = {0};
    if (pwd != nullptr) {
        strncpy(pwd_name, pwd->pw_name, strnlen(pwd->pw_name, 256));
    }

    j = json{
        { "pid", (int32_t)pid },
        { "path", path },
        { "uid", (uint32_t)uid },
        { "username", pwd_name }
    };
}

void to_json(json& j, const NEFilterSocketFlow* f) {
    j = json{
        { "direction", traffic_direction_names[(int)f.direction] },
        { "socketProtocol", socket_protocol_names[f.socketProtocol] },
        { "socketFamily", socket_family_names[f.socketFamily] },
        { "socketType", socket_type_names[f.socketType] },
        { "remoteHostname", f.remoteHostname },
        { "remoteEndpoint", (NWHostEndpoint*)f.remoteEndpoint },
        { "localEndpoint", (NWHostEndpoint*)f.localEndpoint },
        { "sourceApp", (audit_token_t*)f.sourceAppAuditToken.bytes },
        { "sourceProcess", (audit_token_t*)f.sourceProcessAuditToken.bytes }
    };

    if (f.URL != nil) {
        j["URL"] = f.URL;
    }
}
