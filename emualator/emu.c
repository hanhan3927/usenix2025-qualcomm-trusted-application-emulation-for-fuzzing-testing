#include <capstone/capstone.h>
#include <unicorn/unicorn.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <elf.h>
#include <string.h>


static void hook_code(uc_engine *uc, uint64_t address, uint32_t size,void *user_data){
	uint64_t pc , x0 ,x1 ,x2;
	uc_reg_read(uc,UC_ARM64_REG_PC,&pc);

	// #### debug usage ####
	// disasm(uc,pc,8);
	// dump_reg(uc);
	// hook_cmnlib(uc,pc);
	if (pc == 0x1AE0){
		uc_reg_read(uc,UC_ARM64_REG_X0,&x0);
		uc_reg_read(uc,UC_ARM64_REG_X1,&x1);
		uc_reg_read(uc,UC_ARM64_REG_X2,&x2);

		printf("Memcpy x0 : 0x%x\n",x0);
		printf("Memcpy x1 : 0x%x\n",x1);
		printf("Memcpy x2 : 0x%x\n",x2);

	}
}

static const uint64_t INSAMPLE = 0x400000;
static const int64_t INPUT_SIZE_MAX = 0x1000;
static const uint64_t OUTSAMPLE = 0x500000;

static const int64_t ALIGNMENT = 0x1000;


void setup_decrypt_CTR_unified(uc_engine *uc){

	unsigned int x0 = 0;
	unsigned long insample = INSAMPLE ;
	unsigned int x2 = 0x100;
	unsigned int x4 = 0xff;
	unsigned int x5 = 0;
	unsigned long outsample = OUTSAMPLE;


	void *x7 = 0x500000 ;
	void *x9 = 0x400000 ;


	uc_reg_write(uc,UC_ARM64_REG_X0 , &x0);
	mem_write_wrapper(uc , 0x341E8 , 1); //section table
	uc_reg_write(uc,UC_ARM64_REG_X1 , &insample);
	uc_reg_write(uc,UC_ARM64_REG_X2 , &x2);
	uc_reg_write(uc,UC_ARM64_REG_X4 , &x4);

	uc_reg_write(uc,UC_ARM64_REG_X5 , &x5);
	uc_reg_write(uc,UC_ARM64_REG_X6 , &outsample);
	uc_reg_write(uc,UC_ARM64_REG_X7 , &x7);
	//according to stack address 
	mem_write_wrapper(uc , 0x280018 , 0xf3	);
	mem_write_wrapper(uc , 0x280010 , 0x1f2	);

	mem_write_wrapper(uc , 0x280008 , 0xf1);
	
	mem_write_wrapper(uc , 0x280000 , 0xf0);
	// hexdump(uc,0x280008 , 4);




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
	
	if (argc != 2){
		puts("Please input trust application !");
		exit(0);
	}

	char *ta_file = argv[1];
	err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM , &uc);
	if (err){
		printf("Failed uc_open %u\n",err);
	}
	parse_header(uc,ta_file);


	mem_map_checked(uc, INSAMPLE, INPUT_SIZE_MAX, UC_PROT_ALL);
	mem_map_checked(uc, OUTSAMPLE, INPUT_SIZE_MAX, UC_PROT_ALL);

	
	uc_hook trace1 ;
	// Start , End address need to trace by different situation ! 
	// for example code segment
	// If encounter  Invalid memory read (UC_ERR_READ_UNMAPPED) please open debug mode to trace !
	// Maybe function call argument not set correctness !

	uc_hook_add(uc, &trace1 , UC_HOOK_CODE , hook_code ,NULL , 0 , 0x2f0000);
    // // 。uc_hook_add(uc, &trace2, UC_HOOK_MEM_UNMAPPED, hook_memalloc, NULL, 1, 0);

	setup_decrypt_CTR_unified(uc);
	//hexdump(uc,0x6230bc);
	//memcpy()
	//Can specific 0x6230bc ~ 0x6230c8 for libcmnlib function testing , if encouter error add the hook can solve it !
	// 0xf924 is for an example to test
	err = uc_emu_start(uc, 0xf924 , 0xf928 , 0 , 0);
	if (err){
		printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));	
	}

}

