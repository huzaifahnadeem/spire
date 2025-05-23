// struct Switcher_Message {
//     std::string new_active_system_id = "";
//     std::string add_io_proc_path = "";
//     std::string add_io_proc_spinesd_addr = "";
//     std::string add_io_proc_id = "";
//     std::string remove_io_proc_id = "";
// };

// TODO: changed these from std::string to char[]. std::string does feel like the right choice but its causing issues when we receive it on the other end like seg faults. so probably need to handle it more smartly by including lengths and stuff
struct Switcher_Message {
    char new_active_system_id[50]     = "";
    char add_io_proc_path[50]         = "";
    char add_io_proc_spinesd_addr[50] = "";
    char add_io_proc_id[50]           = "";
    char remove_io_proc_id[50]        = "";
};