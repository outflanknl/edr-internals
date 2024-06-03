#pragma once

#include <EndpointSecurity/EndpointSecurity.h>

#include "es_json.hpp"

using Serializer = json (*)(const es_events_t&);

using EventMetadata = struct {
    const char* type_name;
    Serializer serialize_fn;
};

#define DEFINE_SERIALIZER(name) \
    inline static json serialize_##name(const es_events_t& e) { return json{ e.name }; }

#define DEFINE_PTR_SERIALIZER(name) \
    inline static json serialize_##name(const es_events_t& e) { return json{ *e.name }; }

DEFINE_SERIALIZER(exec)
DEFINE_SERIALIZER(open)
DEFINE_SERIALIZER(kextload)
DEFINE_SERIALIZER(mmap)
DEFINE_SERIALIZER(mprotect)
DEFINE_SERIALIZER(mount)
DEFINE_SERIALIZER(rename)
DEFINE_SERIALIZER(signal)
DEFINE_SERIALIZER(unlink)
DEFINE_SERIALIZER(fork)
DEFINE_SERIALIZER(close)
DEFINE_SERIALIZER(create)
DEFINE_SERIALIZER(exchangedata)
DEFINE_SERIALIZER(exit)
DEFINE_SERIALIZER(get_task)
DEFINE_SERIALIZER(kextunload)
DEFINE_SERIALIZER(link)
DEFINE_SERIALIZER(unmount)
DEFINE_SERIALIZER(iokit_open)
DEFINE_SERIALIZER(setattrlist)
DEFINE_SERIALIZER(setextattr)
DEFINE_SERIALIZER(setflags)
DEFINE_SERIALIZER(setmode)
DEFINE_SERIALIZER(setowner)
DEFINE_SERIALIZER(write)
DEFINE_SERIALIZER(file_provider_materialize)
DEFINE_SERIALIZER(file_provider_update)
DEFINE_SERIALIZER(readlink)
DEFINE_SERIALIZER(truncate)
DEFINE_SERIALIZER(lookup)
DEFINE_SERIALIZER(chdir)
DEFINE_SERIALIZER(getattrlist)
DEFINE_SERIALIZER(stat)
DEFINE_SERIALIZER(access)
DEFINE_SERIALIZER(chroot)
DEFINE_SERIALIZER(utimes)
DEFINE_SERIALIZER(clone)
DEFINE_SERIALIZER(fcntl)
DEFINE_SERIALIZER(getextattr)
DEFINE_SERIALIZER(listextattr)
DEFINE_SERIALIZER(readdir)
DEFINE_SERIALIZER(deleteextattr)
DEFINE_SERIALIZER(fsgetpath)
DEFINE_SERIALIZER(dup)
DEFINE_SERIALIZER(settime)
DEFINE_SERIALIZER(uipc_bind)
DEFINE_SERIALIZER(uipc_connect)
DEFINE_SERIALIZER(setacl)
DEFINE_SERIALIZER(pty_grant)
DEFINE_SERIALIZER(pty_close)
DEFINE_SERIALIZER(proc_check)
DEFINE_SERIALIZER(searchfs)
DEFINE_SERIALIZER(proc_suspend_resume)
DEFINE_SERIALIZER(cs_invalidated)
DEFINE_SERIALIZER(get_task_name)
DEFINE_SERIALIZER(trace)
DEFINE_SERIALIZER(remote_thread_create)
DEFINE_SERIALIZER(remount)
DEFINE_SERIALIZER(get_task_read)
DEFINE_SERIALIZER(get_task_inspect)
DEFINE_SERIALIZER(setuid)
DEFINE_SERIALIZER(setgid)
DEFINE_SERIALIZER(seteuid)
DEFINE_SERIALIZER(setegid)
DEFINE_SERIALIZER(setreuid)
DEFINE_SERIALIZER(setregid)
DEFINE_SERIALIZER(copyfile)

DEFINE_PTR_SERIALIZER(authentication)
DEFINE_PTR_SERIALIZER(xp_malware_detected)
DEFINE_PTR_SERIALIZER(xp_malware_remediated)
DEFINE_PTR_SERIALIZER(lw_session_login)
DEFINE_PTR_SERIALIZER(lw_session_logout)
DEFINE_PTR_SERIALIZER(lw_session_lock)
DEFINE_PTR_SERIALIZER(lw_session_unlock)
DEFINE_PTR_SERIALIZER(screensharing_attach)
DEFINE_PTR_SERIALIZER(screensharing_detach)
DEFINE_PTR_SERIALIZER(openssh_login)
DEFINE_PTR_SERIALIZER(openssh_logout)
DEFINE_PTR_SERIALIZER(login_login)
DEFINE_PTR_SERIALIZER(login_logout)
DEFINE_PTR_SERIALIZER(btm_launch_item_add)
DEFINE_PTR_SERIALIZER(btm_launch_item_remove)
DEFINE_PTR_SERIALIZER(profile_add)
DEFINE_PTR_SERIALIZER(profile_remove)
DEFINE_PTR_SERIALIZER(su)
DEFINE_PTR_SERIALIZER(authorization_petition)
DEFINE_PTR_SERIALIZER(authorization_judgement)
DEFINE_PTR_SERIALIZER(sudo)
DEFINE_PTR_SERIALIZER(od_group_add)
DEFINE_PTR_SERIALIZER(od_group_remove)
DEFINE_PTR_SERIALIZER(od_group_set)
DEFINE_PTR_SERIALIZER(od_modify_password)
DEFINE_PTR_SERIALIZER(od_disable_user)
DEFINE_PTR_SERIALIZER(od_enable_user)
DEFINE_PTR_SERIALIZER(od_attribute_value_add)
DEFINE_PTR_SERIALIZER(od_attribute_value_remove)
DEFINE_PTR_SERIALIZER(od_attribute_set)
DEFINE_PTR_SERIALIZER(od_create_user)
DEFINE_PTR_SERIALIZER(od_create_group)
DEFINE_PTR_SERIALIZER(od_delete_user)
DEFINE_PTR_SERIALIZER(od_delete_group)
DEFINE_PTR_SERIALIZER(xpc_connect)

constexpr std::array<EventMetadata, 146> event_data = {
    EventMetadata{"ES_EVENT_TYPE_AUTH_EXEC", serialize_exec},
    EventMetadata{"ES_EVENT_TYPE_AUTH_OPEN", serialize_open},
    EventMetadata{"ES_EVENT_TYPE_AUTH_KEXTLOAD", serialize_kextload},
    EventMetadata{"ES_EVENT_TYPE_AUTH_MMAP", serialize_mmap},
    EventMetadata{"ES_EVENT_TYPE_AUTH_MPROTECT", serialize_mprotect},
    EventMetadata{"ES_EVENT_TYPE_AUTH_MOUNT", serialize_mount},
    EventMetadata{"ES_EVENT_TYPE_AUTH_RENAME", serialize_rename},
    EventMetadata{"ES_EVENT_TYPE_AUTH_SIGNAL", serialize_signal},
    EventMetadata{"ES_EVENT_TYPE_AUTH_UNLINK", serialize_unlink},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_EXEC", serialize_exec},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OPEN", serialize_open},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_FORK", serialize_fork},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_CLOSE", serialize_close},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_CREATE", serialize_create},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA", serialize_exchangedata},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_EXIT", serialize_exit},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_GET_TASK", serialize_get_task},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_KEXTLOAD", serialize_kextload},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_KEXTUNLOAD", serialize_kextunload},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_LINK", serialize_link},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_MMAP", serialize_mmap},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_MPROTECT", serialize_mprotect},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_MOUNT", serialize_mount},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_UNMOUNT", serialize_unmount},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_IOKIT_OPEN", serialize_iokit_open},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_RENAME", serialize_rename},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETATTRLIST", serialize_setattrlist},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETEXTATTR", serialize_setextattr},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETFLAGS", serialize_setflags},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETMODE", serialize_setmode},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETOWNER", serialize_setowner},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SIGNAL", serialize_signal},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_UNLINK", serialize_unlink},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_WRITE", serialize_write},
    EventMetadata{"ES_EVENT_TYPE_AUTH_FILE_PROVIDER_MATERIALIZE", serialize_file_provider_materialize},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_MATERIALIZE", serialize_file_provider_materialize},
    EventMetadata{"ES_EVENT_TYPE_AUTH_FILE_PROVIDER_UPDATE", serialize_file_provider_update},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_FILE_PROVIDER_UPDATE", serialize_file_provider_update},
    EventMetadata{"ES_EVENT_TYPE_AUTH_READLINK", serialize_readlink},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_READLINK", serialize_readlink},
    EventMetadata{"ES_EVENT_TYPE_AUTH_TRUNCATE", serialize_truncate},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_TRUNCATE", serialize_truncate},
    EventMetadata{"ES_EVENT_TYPE_AUTH_LINK", serialize_link},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_LOOKUP", serialize_lookup},
    EventMetadata{"ES_EVENT_TYPE_AUTH_CREATE", serialize_create},
    EventMetadata{"ES_EVENT_TYPE_AUTH_SETATTRLIST", serialize_setattrlist},
    EventMetadata{"ES_EVENT_TYPE_AUTH_SETEXTATTR", serialize_setextattr},
    EventMetadata{"ES_EVENT_TYPE_AUTH_SETFLAGS", serialize_setflags},
    EventMetadata{"ES_EVENT_TYPE_AUTH_SETMODE", serialize_setmode},
    EventMetadata{"ES_EVENT_TYPE_AUTH_SETOWNER", serialize_setowner},
    EventMetadata{"ES_EVENT_TYPE_AUTH_CHDIR", serialize_chdir},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_CHDIR", serialize_chdir},
    EventMetadata{"ES_EVENT_TYPE_AUTH_GETATTRLIST", serialize_getattrlist},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_GETATTRLIST", serialize_getattrlist},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_STAT", serialize_stat},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_ACCESS", serialize_access},
    EventMetadata{"ES_EVENT_TYPE_AUTH_CHROOT", serialize_chroot},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_CHROOT", serialize_chroot},
    EventMetadata{"ES_EVENT_TYPE_AUTH_UTIMES", serialize_utimes},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_UTIMES", serialize_utimes},
    EventMetadata{"ES_EVENT_TYPE_AUTH_CLONE", serialize_clone},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_CLONE", serialize_clone},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_FCNTL", serialize_fcntl},
    EventMetadata{"ES_EVENT_TYPE_AUTH_GETEXTATTR", serialize_getextattr},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_GETEXTATTR", serialize_getextattr},
    EventMetadata{"ES_EVENT_TYPE_AUTH_LISTEXTATTR", serialize_listextattr},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_LISTEXTATTR", serialize_listextattr},
    EventMetadata{"ES_EVENT_TYPE_AUTH_READDIR", serialize_readdir},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_READDIR", serialize_readdir},
    EventMetadata{"ES_EVENT_TYPE_AUTH_DELETEEXTATTR", serialize_deleteextattr},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR", serialize_deleteextattr},
    EventMetadata{"ES_EVENT_TYPE_AUTH_FSGETPATH", serialize_fsgetpath},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_FSGETPATH", serialize_fsgetpath},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_DUP", serialize_dup},
    EventMetadata{"ES_EVENT_TYPE_AUTH_SETTIME", serialize_settime},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETTIME", serialize_settime},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_UIPC_BIND", serialize_uipc_bind},
    EventMetadata{"ES_EVENT_TYPE_AUTH_UIPC_BIND", serialize_uipc_bind},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT", serialize_uipc_connect},
    EventMetadata{"ES_EVENT_TYPE_AUTH_UIPC_CONNECT", serialize_uipc_connect},
    EventMetadata{"ES_EVENT_TYPE_AUTH_EXCHANGEDATA", serialize_exchangedata},
    EventMetadata{"ES_EVENT_TYPE_AUTH_SETACL", serialize_setacl},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETACL", serialize_setacl},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_PTY_GRANT", serialize_pty_grant},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_PTY_CLOSE", serialize_pty_close},
    EventMetadata{"ES_EVENT_TYPE_AUTH_PROC_CHECK", serialize_proc_check},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_PROC_CHECK", serialize_proc_check},
    EventMetadata{"ES_EVENT_TYPE_AUTH_GET_TASK", serialize_get_task},
    EventMetadata{"ES_EVENT_TYPE_AUTH_SEARCHFS", serialize_searchfs},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SEARCHFS", serialize_searchfs},
    EventMetadata{"ES_EVENT_TYPE_AUTH_FCNTL", serialize_fcntl},
    EventMetadata{"ES_EVENT_TYPE_AUTH_IOKIT_OPEN", serialize_iokit_open},
    EventMetadata{"ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME", serialize_proc_suspend_resume},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME", serialize_proc_suspend_resume},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED", serialize_cs_invalidated},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME", serialize_get_task_name},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_TRACE", serialize_trace},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE", serialize_remote_thread_create},
    EventMetadata{"ES_EVENT_TYPE_AUTH_REMOUNT", serialize_remount},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_REMOUNT", serialize_remount},
    EventMetadata{"ES_EVENT_TYPE_AUTH_GET_TASK_READ", serialize_get_task_read},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_GET_TASK_READ", serialize_get_task_read},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_GET_TASK_INSPECT", serialize_get_task_inspect},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETUID", serialize_setuid},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETGID", serialize_setgid},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETEUID", serialize_seteuid},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETEGID", serialize_setegid},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETREUID", serialize_setreuid},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SETREGID", serialize_setregid},
    EventMetadata{"ES_EVENT_TYPE_AUTH_COPYFILE", serialize_copyfile},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_COPYFILE", serialize_copyfile},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_AUTHENTICATION", serialize_authentication},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED", serialize_xp_malware_detected},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED", serialize_xp_malware_remediated},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN", serialize_lw_session_login},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT", serialize_lw_session_logout},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK", serialize_lw_session_lock},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK", serialize_lw_session_unlock},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH", serialize_screensharing_attach},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH", serialize_screensharing_detach},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN", serialize_openssh_login},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT", serialize_openssh_logout},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN", serialize_login_login},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT", serialize_login_logout},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD", serialize_btm_launch_item_add},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE", serialize_btm_launch_item_remove},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_PROFILE_ADD", serialize_profile_add},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE", serialize_profile_remove},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SU", serialize_su},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_PETITION", serialize_authorization_petition},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_AUTHORIZATION_JUDGEMENT", serialize_authorization_judgement},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_SUDO", serialize_sudo},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD", serialize_od_group_add},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE", serialize_od_group_remove},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_GROUP_SET", serialize_od_group_set},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_MODIFY_PASSWORD", serialize_od_modify_password},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_DISABLE_USER", serialize_od_disable_user},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_ENABLE_USER", serialize_od_enable_user},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_ADD", serialize_od_attribute_value_add},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_VALUE_REMOVE", serialize_od_attribute_value_remove},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_ATTRIBUTE_SET", serialize_od_attribute_set},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_CREATE_USER", serialize_od_create_user},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_CREATE_GROUP", serialize_od_create_group},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_DELETE_USER", serialize_od_delete_user},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP", serialize_od_delete_group},
    EventMetadata{"ES_EVENT_TYPE_NOTIFY_XPC_CONNECT", serialize_xpc_connect}
};
