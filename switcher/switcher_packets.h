// struct Switcher_Message {
//     std::string new_active_system_id = "";
//     std::string add_io_proc_path = "";
//     std::string add_io_proc_spinesd_addr = "";
//     std::string add_io_proc_id = "";
//     std::string remove_io_proc_id = "";
// };

struct Switcher_Message {
    char new_active_system_id[5]     = "";
    char add_io_proc_path[5]         = "";
    char add_io_proc_spinesd_addr[5] = "";
    char add_io_proc_id[5]           = "";
    char remove_io_proc_id[5]        = "";
};