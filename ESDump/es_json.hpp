#pragma once

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <pwd.h>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

using create_destination_type_new_path = struct {
    es_file_t* dir;
    es_string_token_t filename;
    mode_t mode;
};

using rename_destination_type_new_path = struct {
    es_file_t* dir;
    es_string_token_t filename;
};

using rename_destination_type_existing_file = struct {
    es_file_t* existing_file;
};

constexpr std::array<const char*, 5> btm_item_type_names = {
    "ES_BTM_ITEM_TYPE_USER_ITEM",
    "ES_BTM_ITEM_TYPE_APP",
    "ES_BTM_ITEM_TYPE_LOGIN_ITEM",
    "ES_BTM_ITEM_TYPE_AGENT",
    "ES_BTM_ITEM_TYPE_DAEMON"
};

constexpr std::array<const char*, 15> proc_check_type_names = {
    nullptr,
    "ES_PROC_CHECK_TYPE_LISTPIDS",
    "ES_PROC_CHECK_TYPE_PIDINFO",
    "ES_PROC_CHECK_TYPE_PIDFDINFO",
    "ES_PROC_CHECK_TYPE_KERNMSGBUF",
    "ES_PROC_CHECK_TYPE_SETCONTROL",
    "ES_PROC_CHECK_TYPE_PIDFILEPORTINFO",
    "ES_PROC_CHECK_TYPE_TERMINATE",
    "ES_PROC_CHECK_TYPE_DIRTYCONTROL",
    "ES_PROC_CHECK_TYPE_PIDRUSAGE",
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    "ES_PROC_CHECK_TYPE_UDATA_INFO",
};

constexpr std::array<const char*, 4> proc_suspend_resume_type_names = {
    "ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND",
    "ES_PROC_SUSPEND_RESUME_TYPE_RESUME",
    nullptr,
    "ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS",
};

constexpr std::array<const char*, 3> es_get_task_type_names = {
    "ES_GET_TASK_TYPE_TASK_FOR_PID",
    "ES_GET_TASK_TYPE_EXPOSE_TASK",
    "ES_GET_TASK_TYPE_IDENTITY_TOKEN",
};

constexpr std::array<const char*, 2> es_touchid_mode_names = {
    "ES_TOUCHID_MODE_VERIFICATION",
    "ES_TOUCHID_MODE_IDENTIFICATION",
};

constexpr std::array<const char*, 3> es_auto_unlock_type_names = {
    nullptr,
    "ES_AUTO_UNLOCK_MACHINE_UNLOCK",
    "ES_AUTO_UNLOCK_AUTH_PROMPT",
};

constexpr std::array<const char*, 10> es_openssh_login_result_type_names = {
    "ES_OPENSSH_LOGIN_EXCEED_MAXTRIES",
    "ES_OPENSSH_LOGIN_ROOT_DENIED",
    "ES_OPENSSH_AUTH_SUCCESS",
    "ES_OPENSSH_AUTH_FAIL_NONE",
    "ES_OPENSSH_AUTH_FAIL_PASSWD",
    "ES_OPENSSH_AUTH_FAIL_KBDINT",
    "ES_OPENSSH_AUTH_FAIL_PUBKEY",
    "ES_OPENSSH_AUTH_FAIL_HOSTBASED",
    "ES_OPENSSH_AUTH_FAIL_GSSAPI",
    "ES_OPENSSH_INVALID_USER",
};

constexpr std::array<const char*, 2> es_profile_source_names = {
    "ES_PROFILE_SOURCE_MANAGED",
    "ES_PROFILE_SOURCE_INSTALL",
};

constexpr std::array<const char*, 6> es_sudo_plugin_type_names = {
    "ES_SUDO_PLUGIN_TYPE_UNKNOWN",
    "ES_SUDO_PLUGIN_TYPE_FRONT_END",
    "ES_SUDO_PLUGIN_TYPE_POLICY",
    "ES_SUDO_PLUGIN_TYPE_IO",
    "ES_SUDO_PLUGIN_TYPE_AUDIT",
    "ES_SUDO_PLUGIN_TYPE_APPROVAL",
};

constexpr std::array<const char*, 6> es_od_member_type_names = {
    "ES_OD_MEMBER_TYPE_USER_NAME",
    "ES_OD_MEMBER_TYPE_USER_UUID",
    "ES_OD_MEMBER_TYPE_GROUP_UUID",
};

constexpr std::array<const char*, 2> es_od_account_type_names = {
    "ES_OD_ACCOUNT_TYPE_USER",
    "ES_OD_ACCOUNT_TYPE_COMPUTER",
};

constexpr std::array<const char*, 2> es_od_record_type_names = {
    "ES_OD_RECORD_TYPE_USER",
    "ES_OD_RECORD_TYPE_GROUP"
};

constexpr std::array<const char*, 9> es_xpc_domain_type_names = {
    nullptr,
    "ES_XPC_DOMAIN_TYPE_SYSTEM",
    "ES_XPC_DOMAIN_TYPE_USER",
    "ES_XPC_DOMAIN_TYPE_USER_LOGIN",
    "ES_XPC_DOMAIN_TYPE_SESSION",
    "ES_XPC_DOMAIN_TYPE_PID",
    "ES_XPC_DOMAIN_TYPE_MANAGER",
    "ES_XPC_DOMAIN_TYPE_PORT",
    "ES_XPC_DOMAIN_TYPE_GUI",
};

template<typename T>
inline T safe_deref(T* ptr) {
    return ptr ? *ptr : T{};
}
void to_json(json& j, const audit_token_t t) {
    pid_t pid = audit_token_to_pid(t);
    uid_t uid = audit_token_to_euid(t);

    char path[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (proc_pidpath(pid, path, PROC_PIDPATHINFO_MAXSIZE) <= 0) {
        path[0] = '\0';
    }

    struct passwd* pwd = getpwuid(uid);
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

void to_json(json& j, const es_string_token_t& str) {
    j = json{
        {"length", str.length},
        {"data", std::string(str.data, str.length)},
    };
}

void to_json(json& j, const timespec& ts) {
    j = json{
        {"tv_sec", ts.tv_sec},
        {"tv_nsec", ts.tv_nsec},
    };
}

void to_json(json& j, const timeval& ts) {
    j = json{
        {"tv_sec", ts.tv_sec},
        {"tv_usec", ts.tv_usec},
    };
}

void to_json(json& j, const struct stat& s) {
    j = json{
        {"st_dev", s.st_dev},
        {"st_mode", s.st_mode},
        {"st_nlink", s.st_nlink},
        {"st_ino", s.st_ino},
        {"st_uid", s.st_uid},
        {"st_gid", s.st_gid},
        {"st_rdev", s.st_rdev},
        {"st_atimespec", s.st_atimespec},
        {"st_mtimespec", s.st_mtimespec},
        {"st_ctimespec", s.st_ctimespec},
        {"st_birthtimespec", s.st_birthtimespec},
        {"st_size", s.st_size},
        {"st_blocks", s.st_blocks},
        {"st_blksize", s.st_blksize},
        {"st_flags", s.st_flags},
        {"st_gen", s.st_gen},
        {"st_lspare", s.st_lspare},
        {"st_qspare", s.st_qspare},
    };
}

void to_json(json& j, const es_file_t& file) {
    j = json{
        {"path", file.path},
        {"path_truncated", file.path_truncated},
        {"stat", file.stat},
    };
}

void to_json(json& j, const es_process_t& process) {
    j = json{
        {"audit_token", process.audit_token},
        {"ppid", process.ppid},
        {"original_ppid", process.original_ppid},
        {"group_id", process.group_id},
        {"session_id", process.session_id},
        {"codesigning_flags", process.codesigning_flags},
        {"is_platform_binary", process.is_platform_binary},
        {"is_es_client", process.is_es_client},
        {"cdhash", std::vector<uint8_t>(process.cdhash, process.cdhash + sizeof(process.cdhash))},
        {"signing_id", process.signing_id},
        {"team_id", process.team_id},
        {"executable", safe_deref(process.executable)},
        {"tty", safe_deref(process.tty)},
        {"start_time", process.start_time},
        {"responsible_audit_token", process.responsible_audit_token},
        {"parent_audit_token", process.parent_audit_token},
    };
}

void to_json(json& j, const es_event_exec_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"dyld_exec_path", event.dyld_exec_path},
        {"script", safe_deref(event.script)},
        {"cwd", safe_deref(event.cwd)},
        {"last_fd", event.last_fd},
        {"image_cputype", event.image_cputype},
        {"image_cpusubtype", event.image_cpusubtype},
    };
}

void to_json(json& j, const es_event_setflags_t& event) {
    j = json{
        {"flags", event.flags},
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_signal_t& event) {
    j = json{
        {"sig", event.sig},
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_deleteextattr_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"extattr", event.extattr},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const fsid_t& fsid) {
    j = json{
        {"val", fsid.val},
    };
}

void to_json(json& j, const struct statfs& s) {
    j = json{
        {"f_bsize", s.f_bsize},
        {"f_iosize", s.f_iosize},
        {"f_blocks", s.f_blocks},
        {"f_bfree", s.f_bfree},
        {"f_bavail", s.f_bavail},
        {"f_files", s.f_files},
        {"f_ffree", s.f_ffree},
        {"f_fsid", s.f_fsid},
        {"f_owner", s.f_owner},
        {"f_type", s.f_type},
        {"f_flags", s.f_flags},
        {"f_fssubtype", s.f_fssubtype},
        {"f_fstypename", s.f_fstypename},
        {"f_mntonname", s.f_mntonname},
        {"f_mntfromname", s.f_mntfromname},
        {"f_flags_ext", s.f_flags_ext},
        // {"f_reserved", s.f_reserved},
    };
}

void to_json(json& j, const es_event_mount_t& event) {
    j = json{
        {"statfs", safe_deref(event.statfs)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_setextattr_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"extattr", event.extattr},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_setowner_t& event) {
    j = json{
        {"uid", event.uid},
        {"gid", event.gid},
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_exit_t& event) {
    j = json{
        {"stat", event.stat},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_fork_t& event) {
    j = json{
        {"child", safe_deref(event.child)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const create_destination_type_new_path& event) {
    j = json{
        {"dir", safe_deref(event.dir)},
        {"filename", event.filename},
        {"mode", event.mode},
    };
}

void to_json(json& j, const rename_destination_type_new_path& event) {
    j = json{
        {"dir", safe_deref(event.dir)},
        {"filename", event.filename},
    };
}

void to_json(json& j, const rename_destination_type_existing_file& event) {
    j = json{
        {"existing_file", safe_deref(event.existing_file)},
    };
}

void to_json(json& j, const es_event_rename_t& event) {
    j = json{
        {"source", safe_deref(event.source)},
        // {"reserved", event.reserved},
    };

    if (event.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        j["destination_type"] = "ES_DESTINATION_TYPE_NEW_PATH";
        j["destination"] = (rename_destination_type_new_path){
            .dir = event.destination.new_path.dir,
            .filename = event.destination.new_path.filename
        };
    }
    else {
        j["destination_type"] = "ES_DESTINATION_TYPE_EXISTING_FILE";
        j["destination"] = (rename_destination_type_existing_file){
            .existing_file = event.destination.existing_file
        };
    }
}

void to_json(json& j, const es_event_truncate_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_link_t& event) {
    j = json{
        {"source", safe_deref(event.source)},
        {"target_dir", safe_deref(event.target_dir)},
        {"target_filename", event.target_filename},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_unmount_t& event) {
    j = json{
        {"statfs", safe_deref(event.statfs)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_close_t& event) {
    j = json{
        {"modified", event.modified},
        {"target", safe_deref(event.target)},
        {"was_mapped_writable", event.was_mapped_writable},
    };
}

void to_json(json& j, const es_event_open_t& event) {
    j = json{
        {"fflag", event.fflag},
        {"file", safe_deref(event.file)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_setmode_t& event) {
    j = json{
        {"mode", event.mode},
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_clone_t& event) {
    j = json{
        {"source", safe_deref(event.source)},
        {"target_dir", safe_deref(event.target_dir)},
        {"target_name", event.target_name},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, acl_t acl) {
    j = json{
        {"val", acl},
    };
}

void to_json(json& j, const es_event_create_t& event) {
    j = json{
        // {"reserved", event.reserved},
        // {"acl", event.acl},
    };

    if (event.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        j["destination_type"] = "ES_DESTINATION_TYPE_NEW_PATH";
        j["destination"] = (create_destination_type_new_path){
            .dir = event.destination.new_path.dir,
            .filename = event.destination.new_path.filename,
            .mode = event.destination.new_path.mode
        };
    }
    else {
        j["destination_type"] = "ES_DESTINATION_TYPE_EXISTING_FILE";
        j["destination"] = (rename_destination_type_existing_file){
            .existing_file = event.destination.existing_file
        };
    }
}

void to_json(json& j, const es_btm_launch_item_t& item) {
    j = json{
        {"item_type", btm_item_type_names[item.item_type]},
        {"legacy", item.legacy},
        {"managed", item.managed},
        {"uid", item.uid},
        {"item_url", item.item_url},
        {"app_url", item.app_url},
    };
}

void to_json(json& j, const es_event_btm_launch_item_add_t& event) {
    j = json{
        {"instigator", safe_deref(event.instigator)},
        {"app", safe_deref(event.app)},
        {"item", safe_deref(event.item)},
        {"executable_path", event.executable_path},
    };
}

void to_json(json& j, const es_event_unlink_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"parent_dir", safe_deref(event.parent_dir)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_kextload_t& event) {
    j = json{
        {"identifier", event.identifier},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_mmap_t& event) {
    j = json{
        {"protection", event.protection},
        {"max_protection", event.max_protection},
        {"flags", event.flags},
        {"file_pos", event.file_pos},
        {"source", safe_deref(event.source)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_mprotect_t& event) {
    j = json{
        {"protection", event.protection},
        {"address", event.address},
        {"size", event.size},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_exchangedata_t& event) {
    j = json{
        {"file1", safe_deref(event.file1)},
        {"file2", safe_deref(event.file2)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_get_task_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"type", event.type},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_kextunload_t& event) {
    j = json{
        {"identifier", event.identifier},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_iokit_open_t& event) {
    j = json{
        {"user_client_type", event.user_client_type},
        {"user_client_class", event.user_client_class},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const attrlist& list) {
    j = json{
        {"bitmapcount", list.bitmapcount},
        {"reserved", list.reserved},
        {"commonattr", list.commonattr},
        {"volattr", list.volattr},
        {"dirattr", list.dirattr},
        {"fileattr", list.fileattr},
        {"forkattr", list.forkattr},
    };
}

void to_json(json& j, const es_event_setattrlist_t& event) {
    j = json{
        {"attrlist", event.attrlist},
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_write_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_file_provider_materialize_t& event) {
    j = json{
        {"instigator", safe_deref(event.instigator)},
        {"source", safe_deref(event.source)},
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_file_provider_update_t& event) {
    j = json{
        {"source", safe_deref(event.source)},
        {"target_path", event.target_path},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_readlink_t& event) {
    j = json{
        {"source", safe_deref(event.source)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_lookup_t& event) {
    j = json{
        {"source_dir", safe_deref(event.source_dir)},
        {"relative_target", event.relative_target},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_chdir_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_getattrlist_t& event) {
    j = json{
        {"attrlist", event.attrlist},
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_stat_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_access_t& event) {
    j = json{
        {"mode", event.mode},
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_chroot_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_utimes_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"atime", event.atime},
        {"mtime", event.mtime},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_fcntl_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"cmd", event.cmd},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_getextattr_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"extattr", event.extattr},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_listextattr_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_readdir_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_fsgetpath_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_dup_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_settime_t& event) {
    j = json{
        // {"reserved", event.reserved},
    };

    (void)event;
}

void to_json(json& j, const es_event_uipc_bind_t& event) {
    j = json{
        {"dir", safe_deref(event.dir)},
        {"filename", event.filename},
        {"mode", event.mode},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_uipc_connect_t& event) {
    j = json{
        {"file", safe_deref(event.file)},
        {"domain", event.domain},
        {"type", event.type},
        {"protocol", event.protocol},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_setacl_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"set_or_clear", event.set_or_clear},
        // {"acl", event.acl},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_pty_grant_t& event) {
    j = json{
        {"dev", event.dev},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_pty_close_t& event) {
    j = json{
        {"dev", event.dev},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_proc_check_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"type", proc_check_type_names[event.type]},
        {"flavor", event.flavor},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_searchfs_t& event) {
    j = json{
        {"attrlist", event.attrlist},
        {"target", safe_deref(event.target)},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_proc_suspend_resume_t& event) {
    j = json{
        {"target", safe_deref(event.target)},
        {"type", proc_suspend_resume_type_names[event.type]},
        // {"reserved", event.reserved},
    };
}

void to_json(json& j, const es_event_cs_invalidated_t& event) {
    j = json{
        // {"reserved", event.reserved},
    };

    (void)event;
}

void to_json(json& j, const es_event_get_task_name_t& event) {
	j = json{
		{"target", safe_deref(event.target)},
		{"type", es_get_task_type_names[event.type]},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_trace_t& event) {
	j = json{
		{"target", safe_deref(event.target)},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_token_t& event) {
	j = json{
		{"size", event.size},
		{"data", std::vector<uint8_t>(event.data, event.data + event.size)},
	};
}

void to_json(json& j, const es_thread_state_t& event) {
    j = json{
		{"flavor", event.flavor},
        {"state", event.state}
    };
}

void to_json(json& j, const es_event_remote_thread_create_t& event) {
	j = json{
		{"target", safe_deref(event.target)},
		{"thread_state", safe_deref(event.thread_state)},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_remount_t& event) {
	j = json{
		{"statfs", safe_deref(event.statfs)},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_get_task_read_t& event) {
	j = json{
		{"target", safe_deref(event.target)},
		{"type", es_get_task_type_names[event.type]},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_get_task_inspect_t& event) {
	j = json{
		{"target", safe_deref(event.target)},
		{"type", es_get_task_type_names[event.type]},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_setuid_t& event) {
	j = json{
		{"uid", event.uid},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_setgid_t& event) {
	j = json{
		{"gid", event.gid},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_seteuid_t& event) {
	j = json{
		{"euid", event.euid},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_setegid_t& event) {
	j = json{
		{"egid", event.egid},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_setreuid_t& event) {
	j = json{
		{"ruid", event.ruid},
		{"euid", event.euid},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_setregid_t& event) {
	j = json{
		{"rgid", event.rgid},
		{"egid", event.egid},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_copyfile_t& event) {
	j = json{
		{"source", safe_deref(event.source)},
		{"target_file", safe_deref(event.target_file)},
		{"target_dir", safe_deref(event.target_dir)},
		{"target_name", event.target_name},
		{"mode", event.mode},
		{"flags", event.flags},
		// {"reserved", event.reserved},
	};
}

void to_json(json& j, const es_event_authentication_od_t& event) {
	j = json{
		{"instigator", safe_deref(event.instigator)},
		{"record_type", event.record_type},
		{"record_name", event.record_name},
		{"node_name", event.node_name},
		{"db_path", event.db_path},
	};
}

void to_json(json& j, const es_event_authentication_touchid_t& event) {
	j = json{
		{"instigator", safe_deref(event.instigator)},
		{"touchid_mode", es_touchid_mode_names[event.touchid_mode]},
		{"has_uid", event.has_uid},
	};

    if (event.has_uid) {
        j["uid"] = event.uid.uid;
    }
}

void to_json(json& j, const es_event_authentication_token_t& event) {
	j = json{
		{"instigator", safe_deref(event.instigator)},
		{"pubkey_hash", event.pubkey_hash},
		{"token_id", event.token_id},
		{"kerberos_principal", event.kerberos_principal},
	};
}

void to_json(json& j, const es_event_authentication_auto_unlock_t& event) {
	j = json{
		{"username", event.username},
		{"type", es_auto_unlock_type_names[event.type]},
	};
}

void to_json(json& j, const es_event_authentication_t& event) {
    j = json{
        {"success", event.success},
    };

    if (event.type == ES_AUTHENTICATION_TYPE_OD) {
        j["type"] = "ES_AUTHENTICATION_TYPE_OD";
        j["data"] = safe_deref(event.data.od);
    }
    else if (event.type == ES_AUTHENTICATION_TYPE_TOUCHID) {
        j["type"] = "ES_AUTHENTICATION_TYPE_TOUCHID";
        j["data"] = safe_deref(event.data.touchid);
    }
    else if (event.type == ES_AUTHENTICATION_TYPE_TOKEN) {
        j["type"] = "ES_AUTHENTICATION_TYPE_TOKEN";
        j["data"] = safe_deref(event.data.token);
    }
    else if (event.type == ES_AUTHENTICATION_TYPE_AUTO_UNLOCK) {
        j["type"] = "ES_AUTHENTICATION_TYPE_AUTO_UNLOCK";
        j["data"] = safe_deref(event.data.auto_unlock);
    }
}

void to_json(json& j, const es_event_xp_malware_detected_t& event) {
	j = json{
		{"signature_version", event.signature_version},
		{"malware_identifier", event.malware_identifier},
		{"incident_identifier", event.incident_identifier},
		{"detected_path", event.detected_path},
	};
}

void to_json(json& j, const es_event_xp_malware_remediated_t& event) {
	j = json{
		{"signature_version", event.signature_version},
		{"malware_identifier", event.malware_identifier},
		{"incident_identifier", event.incident_identifier},
		{"action_type", event.action_type},
		{"success", event.success},
		{"result_description", event.result_description},
		{"remediated_path", event.remediated_path},
		{"remediated_process_audit_token", safe_deref(event.remediated_process_audit_token)},
	};
}

void to_json(json& j, const es_event_lw_session_login_t& event) {
	j = json{
		{"username", event.username},
		{"graphical_session_id", event.graphical_session_id},
	};
}

void to_json(json& j, const es_event_lw_session_logout_t& event) {
	j = json{
		{"username", event.username},
		{"graphical_session_id", event.graphical_session_id},
	};
}

void to_json(json& j, const es_event_lw_session_lock_t& event) {
	j = json{
		{"username", event.username},
		{"graphical_session_id", event.graphical_session_id},
	};
}

void to_json(json& j, const es_event_lw_session_unlock_t& event) {
	j = json{
		{"username", event.username},
		{"graphical_session_id", event.graphical_session_id},
	};
}

void to_json(json& j, const es_event_screensharing_attach_t& event) {
	j = json{
		{"success", event.success},
		{"source_address_type", event.source_address_type},
		{"source_address", event.source_address},
		{"viewer_appleid", event.viewer_appleid},
		{"authentication_type", event.authentication_type},
		{"authentication_username", event.authentication_username},
		{"session_username", event.session_username},
		{"existing_session", event.existing_session},
		{"graphical_session_id", event.graphical_session_id},
	};
}

void to_json(json& j, const es_event_screensharing_detach_t& event) {
	j = json{
		{"source_address_type", event.source_address_type},
		{"source_address", event.source_address},
		{"viewer_appleid", event.viewer_appleid},
		{"graphical_session_id", event.graphical_session_id},
	};
}

void to_json(json& j, const es_event_openssh_login_t& event) {
    j = json{
		{"success", event.success},
        {"result_type", es_openssh_login_result_type_names[event.result_type]},
        {"source_address_type", event.source_address_type},
        {"source_address", event.source_address},
        {"username", event.username},
        {"has_uid", event.has_uid},
        {"uid", event.uid.uid},
    };
}

void to_json(json& j, const es_event_openssh_logout_t& event) {
    j = json{
		{"source_address_type", event.source_address_type},
        {"source_address", event.source_address},
        {"username", event.username},
        {"uid", event.uid},
    };
}


void to_json(json& j, const es_event_login_login_t& event) {
    j = json{
		{"success", event.success},
        {"failure_message", event.failure_message},
        {"username", event.username},
        {"has_uid", event.has_uid},
    };

    if (event.has_uid) {
        j["uid"] = event.uid.uid;
    }
}

void to_json(json& j, const es_event_btm_launch_item_remove_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"app", safe_deref(event.app)},
        {"item", safe_deref(event.item)}
    };
}

void to_json(json& j, const es_event_login_logout_t& event) {
    j = json{
		{"username", event.username},
        {"uid", event.uid}
    };
}

void to_json(json& j, const es_profile_t& profile) {
    j = json{
		{"identifier", profile.identifier},
        {"uuid", profile.uuid},
        {"install_source", es_profile_source_names[profile.install_source]},
        {"organization", profile.organization},
        {"display_name", profile.display_name},
        {"scope", profile.scope}
    };
}

void to_json(json& j, const es_event_profile_add_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"is_update", event.is_update},
        {"profile", safe_deref(event.profile)},
    };
}

void to_json(json& j, const es_event_profile_remove_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"profile", safe_deref(event.profile)},
    };
}

void to_json(json& j, const es_event_su_t& event) {
    j = json{
		{"success", event.success},
        {"failure_message", event.failure_message},
        {"from_uid", event.from_uid},
        {"from_username", event.from_username},
        {"has_to_uid", event.has_to_uid},
        {"to_username", event.to_username},
        {"shell", event.shell},
        {"argc", event.argc},
        {"argv", safe_deref(event.argv)},
        {"env_count", event.env_count},
        {"env", safe_deref(event.env)}
    };

    if (event.has_to_uid) {
        j["to_uid"] = event.to_uid.uid;
    }
}

void to_json(json& j, const es_event_authorization_petition_t& event) {
	j = json{
		{"instigator", safe_deref(event.instigator)},
		{"petitioner", safe_deref(event.petitioner)},
		{"flags", event.flags},
		{"right_count", event.right_count},
	};

	if (event.right_count > 0) {
		j["rights"] = safe_deref(event.rights);
	}
}

void to_json(json& j, const es_authorization_result_t& event) {
    j = json{
        {"right_name", event.right_name},
        {"rule_class", event.rule_class},
        {"granted", event.granted}
    };
}

void to_json(json &j, const es_event_authorization_judgement_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"petitioner", safe_deref(event.petitioner)},
        {"return_code", event.return_code},
        {"result_count", event.result_count}
    };

    for (size_t i = 0; i < event.result_count; i++) {
        j["results"][i] = event.results[i];
    }
}

void to_json(json& j, const es_sudo_reject_info_t& event) {
	j = json{
		{"plugin_name", event.plugin_name},
		{"plugin_type", es_sudo_plugin_type_names[event.plugin_type]},
		{"failure_message", event.failure_message}
	};
}

void to_json(json& j, const es_event_sudo_t& event) {
	j = json{
		{"success", event.success},
		{"reject_info", safe_deref(event.reject_info)},
		{"has_from_uid", event.has_from_uid},
		{"from_username", event.from_username},
		{"has_to_uid", event.has_to_uid},
		{"to_username", event.to_username},
		{"command", event.command}
	};

	if (event.has_from_uid) {
		j["from_uid"] = event.from_uid.uid;
	}

	if (event.has_to_uid) {
		j["to_uid"] = event.to_uid.uid;
	}
}

void to_json(json& j, const es_od_member_id_t& event) {
	j = json{
		{"member_type", es_od_member_type_names[event.member_type]}
	};

	if (event.member_type == ES_OD_MEMBER_TYPE_USER_NAME) {
		j["name"] = event.member_value.name;
	}
    else {
		j["uuid"] = event.member_value.uuid;
	}
}

void to_json(json& j, const es_event_od_group_add_t& event) {
	j = json{
		{"instigator", safe_deref(event.instigator)},
		{"error_code", event.error_code},
		{"group_name", event.group_name},
		{"member", safe_deref(event.member)},
		{"node_name", event.node_name},
		{"db_path", event.db_path}
	};
}

void to_json(json& j, const es_event_od_group_remove_t& event) {
	j = json{
		{"instigator", safe_deref(event.instigator)},
		{"error_code", event.error_code},
		{"group_name", event.group_name},
		{"member", safe_deref(event.member)},
		{"node_name", event.node_name},
		{"db_path", event.db_path}
	};
}

void to_json(json& j, const es_od_member_id_array_t& event) {
    j = json{
		{"member_type", es_od_member_type_names[event.member_type]},
        {"member_count", event.member_count},
    };

    for (size_t i = 0; i < event.member_count; i++) {
        if (event.member_type == ES_OD_MEMBER_TYPE_USER_NAME) {
            j["names"][i] = event.member_array.names[i];
        }
        else {
            j["uuids"][i] = event.member_array.uuids[i];
        }
    }
}

void to_json(json& j, const es_event_od_group_set_t& event) {
	j = json{
		{"instigator", safe_deref(event.instigator)},
		{"error_code", event.error_code},
		{"group_name", event.group_name},
		{"members", safe_deref(event.members)},
		{"node_name", event.node_name},
		{"db_path", event.db_path}
	};
}

void to_json(json& j, const es_event_od_modify_password_t& event) {
	j = json{
		{"instigator", safe_deref(event.instigator)},
		{"error_code", event.error_code},
		{"account_type", es_od_account_type_names[event.account_type]},
		{"account_name", event.account_name},
		{"node_name", event.node_name},
		{"db_path", event.db_path}
	};
}

void to_json(json& j, const es_event_od_disable_user_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"error_code", event.error_code},
        {"user_name", event.user_name},
        {"node_name", event.node_name},
        {"db_path", event.db_path}
    };
}

void to_json(json& j, const es_event_od_enable_user_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"error_code", event.error_code},
        {"user_name", event.user_name},
        {"node_name", event.node_name},
        {"db_path", event.db_path}
    };
}

void to_json(json& j, const es_event_od_attribute_value_add_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"error_code", event.error_code},
        {"record_type", es_od_record_type_names[event.record_type]},
        {"record_name", event.record_name},
        {"attribute_name", event.attribute_name},
        {"attribute_value", event.attribute_value},
        {"node_name", event.node_name},
        {"db_path", event.db_path}
    };
}

void to_json(json& j, const es_event_od_attribute_value_remove_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"error_code", event.error_code},
        {"record_type", es_od_record_type_names[event.record_type]},
        {"record_name", event.record_name},
        {"attribute_name", event.attribute_name},
        {"attribute_value", event.attribute_value},
        {"node_name", event.node_name},
        {"db_path", event.db_path}
    };
}

void to_json(json& j, const es_event_od_attribute_set_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"error_code", event.error_code},
        {"record_type", es_od_record_type_names[event.record_type]},
        {"record_name", event.record_name},
        {"attribute_name", event.attribute_name},
        {"attribute_value_count", event.attribute_value_count},
        {"node_name", event.node_name},
        {"db_path", event.db_path}
    };

    for (size_t i = 0; i < event.attribute_value_count; i++) {
        j["attribute_values"][i] = event.attribute_values[i];
    }
}

void to_json(json& j, const es_event_od_create_user_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"error_code", event.error_code},
        {"user_name", event.user_name},
        {"node_name", event.node_name},
        {"db_path", event.db_path}
    };
}

void to_json(json& j, const es_event_od_create_group_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"error_code", event.error_code},
        {"group_name", event.group_name},
        {"node_name", event.node_name},
        {"db_path", event.db_path}
    };
}

void to_json(json& j, const es_event_od_delete_user_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"error_code", event.error_code},
        {"user_name", event.user_name},
        {"node_name", event.node_name},
        {"db_path", event.db_path}
    };
}

void to_json(json& j, const es_event_od_delete_group_t& event) {
    j = json{
		{"instigator", safe_deref(event.instigator)},
        {"error_code", event.error_code},
        {"group_name", event.group_name},
        {"node_name", event.node_name},
        {"db_path", event.db_path}
    };
}

void to_json(json& j, const es_event_xpc_connect_t& event) {
    j = json{
		{"service_name", event.service_name},
        {"service_domain_type", es_xpc_domain_type_names[event.service_domain_type]}
    };
}
