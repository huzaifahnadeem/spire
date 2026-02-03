// This is a simple modbus TCP client that can communicate with a PNNL scenario PLC (or IO process for Ovation). It is meant to test the IO process for Ovation
#include <iostream>
#include <cerrno>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>
// #include "../../../OpenPLC_v2/libmodbus_src/src/modbus.h" // If we want to use libmodbus that comes with OpenPLC
#include <modbus/modbus.h> // can install system-wise like: sudo yum install libmodbus-devel; # or sudo apt-get install libmodbus-dev;

// pnnl scenario:
#define NUM_POINT 8
#define NUM_POINT_ACTUAL 16
#define NUM_BREAKER 14

std::string mb_server_ip; // mb_server = pnnl_plc or io_ovation
int mb_server_port;
modbus_t *ctx = nullptr;

void poll() {
    bool read_fail_inputbits, read_fail_coils, read_fail_regs = false;

    // Read input bits starting from address 0
    uint8_t read_buffer_breakers_input[NUM_BREAKER];
    int bits_to_read_input = NUM_BREAKER;
    int count_inputbits = modbus_read_input_bits(ctx, 0, bits_to_read_input, read_buffer_breakers_input);
    if (count_inputbits == -1) {
        read_fail_inputbits = true;
        std::cerr << "Read failed for input status/discrete input (read-only) bits: " << modbus_strerror(errno) << std::endl;
    }
    
    // Read output bits (coils) starting from address 0
    uint8_t read_buffer_breakers_coil[NUM_BREAKER];
    int bits_to_read_coil = NUM_BREAKER;
    int count_coils = modbus_read_bits(ctx, 0, bits_to_read_coil, read_buffer_breakers_coil);   
    if (count_coils == -1) {
        read_fail_coils = true;
        std::cerr << "Read failed for coils (R/W bits): " << modbus_strerror(errno) << std::endl;
    }

    // Read (output/holding) registers starting from address 0
    uint16_t read_buffer_points[NUM_POINT_ACTUAL]; // the actaul plc has 16 registers but only NUM_POINT=8 are used
    int registers_to_read = NUM_POINT_ACTUAL;

    // modbus_read_registers(context, start_address, quantity, destination_array)
    int count_regs = modbus_read_registers(ctx, 0, registers_to_read, read_buffer_points);
    if (count_regs == -1) {
        read_fail_regs = true;
        std::cerr << "Read failed for holding registers (R/W 16-bit registers): " << modbus_strerror(errno) << std::endl;
    }

    // pretty printing
    int num_rows = NUM_POINT_ACTUAL; // since there are more of registers than bits

    for (int r = 0; r < num_rows; r++) {
        if (r == 0) { // then print heading
            std::cout << " Input Status bits \t Coils \t\t Holding Registers\n";
        }
        // input bits
        if (!read_fail_inputbits && r < NUM_BREAKER)
            std::cout << "  Bit [" << r << "]: " << (read_buffer_breakers_input[r]?"TRUE ":"FALSE") << "\t";
        else 
            std::cout << "\t\t\t";
        // output bits (coils)
        if (!read_fail_coils && r < NUM_BREAKER)
            std::cout << "  Coil [" << r << "]: " << (read_buffer_breakers_coil[r]?"TRUE ":"FALSE") << "\t";
        else 
            std::cout << "\t\t\t";
        // holding registers
        if (!read_fail_regs)
            std::cout << "  Register [" << r << "]: " << read_buffer_points[r] << "\n";
        else
            std::cout << "\n";
    }

}

void write_input_bit(int bit_num, int write_val) {
    if (!(bit_num >=0 && bit_num < NUM_BREAKER)) {
        std::cout << "Invalid coil number entered. Valid options: {0..13}";
        return;
    }
    if (!(write_val == 0 || write_val == 1)) {
        std::cout << "Invalid write val entered. Valid options: {0, 1}";
        return;
    }
    
    int addr = bit_num;
    int value_to_write = write_val;
    
    if (modbus_write_bit(ctx, addr, value_to_write) == 1) {
        std::cout << "Successfully wrote " << value_to_write << " to coil (R/W) bit at addr " << addr << std::endl;
    } else {
        std::cerr << "Write failed: " << modbus_strerror(errno) << std::endl;
    }
}

int modbus_init() {
    // Create a new Modbus TCP context
    // ctx = modbus_new_tcp("192.168.53.29", 502); // aster20's IP addr and our default pnnl client port (must match config/config.json: ID:10)
    ctx = modbus_new_tcp(mb_server_ip.c_str(), mb_server_port);
    
    if (ctx == nullptr) {
        std::cerr << "Unable to create the libmodbus context" << std::endl;
        return EXIT_FAILURE;
    }

    // 2. Connect to the server
    if (modbus_connect(ctx) == -1) {
        std::cerr << "Connection failed: " << modbus_strerror(errno) << std::endl;
        modbus_free(ctx);
        return EXIT_FAILURE;
    }
    
    std::cout << "Connected to Modbus server." << std::endl;
    return EXIT_SUCCESS;
}

int modbus_tcp_client_loop() {
    if (modbus_init()) {
        return EXIT_FAILURE;
    }
    
    std::string user_input;

    bool exit = false;
    while (!exit) {
        std::cout << "\nInput options: `poll`, `exit`, `write <coil_num \\in {0..13}> <value_to_write \\in {0, 1}>`.\n> ";
        std::getline(std::cin, user_input);
        std::stringstream user_input_ss(user_input);
        std::string token;
        std::vector<std::string> tokens;
        // The extraction operator (>>) automatically uses whitespace as a delimiter
        while (user_input_ss >> token) { 
            tokens.push_back(token);
        }

        if (tokens[0] == "exit") {
            exit = true;
        }
        else if (tokens[0] == "poll") {
            poll();
        }
        else if (tokens[0] == "write") {
            write_input_bit(std::stoi(tokens[1]), std::stoi(tokens[2]));
        }
        else {
            std::cout << "Invalid input.\n";
        }
    }

    // Close connection and cleanup
    modbus_close(ctx);
    modbus_free(ctx);

    return EXIT_SUCCESS;
}

int parse_args(int ac, char **av) {
    if (ac != 3) {
        std::cout << "Invalid args\nUsage: ./testprog_ovation_demo ModbusServerIPAddr ModbusServerPort\n";
        return EXIT_FAILURE;
    }
    // by convention av[0] is just the prog name
    mb_server_ip = av[1];
    mb_server_port = atoi(av[2]);
    
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    if (parse_args(argc, argv)) {
        return EXIT_FAILURE;
    }

    return modbus_tcp_client_loop();
}