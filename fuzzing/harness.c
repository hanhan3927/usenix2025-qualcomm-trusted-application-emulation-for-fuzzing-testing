#include <unicornafl/unicornafl.h>
#include <capstone/capstone.h>
#include <unicorn/unicorn.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>
#include <time.h>


static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,void *user_data){
	uint64_t pc , x0 ,x1 ,x2;
	uc_reg_read(uc,UC_ARM64_REG_PC,&pc);
	// printf("PC : %lx\n",pc);

	// disasm(uc,pc,8);
	// dump_reg(uc);
	//hook_cmnlib(uc,pc);
	//uc_reg_write(uc,UC_ARM64_REG_PC,&pc+4);
	
	if (pc == 0x1AE0){
		uc_reg_read(uc,UC_ARM64_REG_X0,&x0);
		uc_reg_read(uc,UC_ARM64_REG_X1,&x1);
		uc_reg_read(uc,UC_ARM64_REG_X2,&x2);

		printf("Memcpy x0 : 0x%x\n",x0);
		printf("Memcpy x1 : 0x%x\n",x1);
		printf("Memcpy x2 : 0x%x\n",x2);

	}


}


static const int64_t CODE_ADDRESS = 0xF924;
static const int64_t END_ADDRESS = 0xF928;
static const int64_t INPUT_LOCATION = 0x50000;
// static const int64_t INPUT_SIZE_MAX = 0x10000;
static const int64_t INPUT_OFFSET = 0x16;
static size_t current_input_len = 0;
static const int64_t ALIGNMENT = 0x1000;

static const uint64_t INSAMPLE = 0x50000;
static const int64_t INPUT_SIZE_MAX = 0x10;
static const uint64_t OUTSAMPLE = 0x60000;


void setup_decrypt_CTR_unified(uc_engine *uc){

	srand(time(NULL));
	int offset; 
	offset = rand() % 0x1200;

	unsigned int x0 = 0;
	unsigned long insample = INSAMPLE + offset ;
	unsigned int x2 = 0x100;
	unsigned int x4 = 0xff;
	unsigned int x5 = 0;
	unsigned long outsample = OUTSAMPLE + offset;


	void *x7 = 0x500000 ;
	uc_reg_write(uc,UC_ARM64_REG_X0 , &x0);
	mem_write_wrapper(uc , 0x341E8 , 1);
	uc_reg_write(uc,UC_ARM64_REG_X1 , &insample);
	uc_reg_write(uc,UC_ARM64_REG_X2 , &x2);
	uc_reg_write(uc,UC_ARM64_REG_X4 , &x4);

	uc_reg_write(uc,UC_ARM64_REG_X5 , &x5);
	uc_reg_write(uc,UC_ARM64_REG_X6 , &outsample);

	uc_reg_write(uc,UC_ARM64_REG_X7 , &x7);
	// uc_reg_write(uc,UC_ARM64_REG_X29 ,&x7);
	mem_write_wrapper(uc , 0x280018 , 0xf3	);
	mem_write_wrapper(uc , 0x280010 , 0x1f2	);

	mem_write_wrapper(uc , 0x280008 , 0xf1);
	
	mem_write_wrapper(uc , 0x280000 , 0xf0);
	// hexdump(uc,0x280008 , 4);

}


static bool place_input_callback(
    uc_engine *uc,
    char *input,
    size_t input_len,
    uint32_t persistent_round,
    void *data
){
    // printf("Placing input with len %ld to %x\n", input_len, DATA_ADDRESS);
    if (input_len < 1 || input_len >= INPUT_SIZE_MAX - INPUT_OFFSET) {
        // Test input too short or too long, ignore this testcase
        return false;
    }

#if defined(AFL_DEBUG)
    printf("[d] harness: input len=%ld, [ ", input_len);
    int i = 0;
    for (i = 0; i < input_len && i < 16; i++) {
        printf("0x%02x ", (unsigned char) input[i]);
    }
    if (input_len > 16) printf("... ");
    printf("]\n");
#endif
    setup_decrypt_CTR_unified(uc); //init args
	
    // For persistent mode, we have to set up stack and memory each time.
    uc_reg_write(uc, UC_ARM64_REG_PC, &CODE_ADDRESS); // Set the instruction pointer back
	
    // We need a valid c string, make sure it never goes out of bounds.
    input[input_len-1] = '\0';
    // Write the testcase to unicorn.
    uc_mem_write(uc, INPUT_LOCATION , input, input_len);

    // store input_len for the faux strlen hook
    current_input_len = input_len;

    return true;
}





static uint64_t pad(uint64_t size) {
    if (size % ALIGNMENT == 0) return size;
    return ((size / ALIGNMENT) + 1) * ALIGNMENT;
}


static void mem_map_checked(uc_engine *uc, uint64_t addr, size_t size, uint32_t mode) {
    size = pad(size);
    //printf("SIZE %llx, align: %llx\n", size, ALIGNMENT);
    uc_err err = uc_mem_map(uc, addr, size, mode);
    if (err != UC_ERR_OK) {
        printf("Error mapping %zu bytes at 0x%llx: %s (mode: %d)\n", size, (unsigned long long) addr, uc_strerror(err), mode);
        exit(1);
    }
}

int main(int argc , char * argv[]){
	
	uc_engine * uc ;
	uc_err err ; 
	
	char *filename = argv[1]; //fuzzing inputs

	if (argc != 2){
		puts("Please select fuzzing input !");
		exit(0);
	}

	// char *ta_file = argv[1];

	char *ta_file = "./pixel4_widevine";

	err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM , &uc);
	if (err){
		printf("Failed uc_open %u\n",err);
	}
	parse_header(uc,ta_file);


	mem_map_checked(uc, INSAMPLE, INPUT_SIZE_MAX, UC_PROT_ALL);
	mem_map_checked(uc, OUTSAMPLE, INPUT_SIZE_MAX, UC_PROT_ALL);


	uc_hook trace1 ;
	uc_hook_add(uc, &trace1 , UC_HOOK_CODE , hook_code ,NULL , 0 , 0x1f000);

	setup_decrypt_CTR_unified(uc);

	uint64_t start_address = CODE_ADDRESS ; 
	uint64_t end_address = END_ADDRESS ; 

	uc_reg_write(uc,UC_ARM64_REG_PC , &start_address );

	uc_afl_ret afl_ret = uc_afl_fuzz(
        uc, // The unicorn instance we prepared
        filename, // Filename of the input to process. In AFL this is usually the '@@' placeholder, outside it's any input file.
        place_input_callback, // Callback that places the input (automatically loaded from the file at filename) in the unicorninstance
        &end_address, // Where to exit (this is an array)
        1,  // Count of end addresses
        NULL, // Optional calback to run after each exec
        false, // true, if the optional callback should be run also for non-crashes
        1000, // For persistent mode: How many rounds to run
        NULL // additional data pointer
    );
    switch(afl_ret) {
        case UC_AFL_RET_ERROR:
            printf("Error starting to fuzz\n");
            return -3;
            break;
        case UC_AFL_RET_NO_AFL:
            printf("No AFL attached - We are done with a single run.\n");
            break;
        default:
            break;
    }
    return 0;
}

