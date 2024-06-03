const module = Process.getModuleByName("libsystem_notify.dylib");
const functions = [
    { name: "notify_register_dispatch", type: "dispatch queue" },
    { name: "notify_register_mach_port", type: "Mach port" },
    { name: "notify_register_signal", type: "signal" },
    { name: "notify_register_file_descriptor", type: "file descriptor" }
];

functions.forEach(f => {
    const func = module.getExportByName(f.name);
    Interceptor.attach(func, {
        onEnter: function (args) {
            const name = args[0].readUtf8String();
            console.log(`[+] Requested notification delivery to a ${f.type} for ${name}`);
        }
    });
});
