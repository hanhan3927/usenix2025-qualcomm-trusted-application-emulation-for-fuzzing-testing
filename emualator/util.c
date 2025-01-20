#include <stdio.h>
#include <elf.h>
#include <string.h>

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>

unsigned long libcmnlib_text_offset = 0x600000 ; 
unsigned int tmp_memseg_size , tmp_map_addr, tmp_map_addr_size = 0;

struct func_info{
	char *func_name;
	unsigned int got_table; //got table[x]
	unsigned int libcmn_position;
};



struct cmnfunc_info{
	char *func_name;
	unsigned int func_value;
};

//err = uc_mem_map(uc , segment_map_addr , segment_align_size , UC_PROT_ALL );
//err = uc_mem_write(uc , segment_map_addr , segment_data , segment_align_size );	

struct file_segment_data{
	unsigned int segment_map_addr;

};

struct func_info func_array[0x100];
struct cmnfunc_info cmn_array[0x200];

void dump_reg(uc_engine *uc){
    char *map[] = {
        "x0", "x1", "x2", "x3","x4", "x5", "x6", "x7","x8", "x9", "x10", "x11","x12", "x13", "x14", "x15",
        "x16", "x17", "x18", "x19","x20", "x21", "x22", "x23","x24", "x25", "x26", "x27","x28", "x29"
	};

    printf("----- Reg Dump -----\n");
	uint64_t pc, fp, lr, sp;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    uc_reg_read(uc, UC_ARM64_REG_FP, &fp);
    uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
    uc_reg_read(uc, UC_ARM64_REG_SP, &sp);
    printf(" pc: 0x%016lx  sp: 0x%016lx\n", pc, sp);
	printf(" fp: 0x%016lx  lr: 0x%016lx\n", fp, lr);

	uint64_t r[32];
    int i = 0;
    for(i = 0; i < 30; i++) {
        uc_reg_read(uc, UC_ARM64_REG_X0 + i, &r[i]);
        if(i % 2 == 0 && i != 0) {
            printf("\n");
        }
        printf("%3s: 0x%016lx ", map[i], r[i]);
    }

    printf("\n");

}


void disasm(uc_engine *uc, uint64_t pc, int num) {
    csh handle;
    cs_insn *insn;
    size_t count;

    printf("----- Disassemble -----\n");
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK)
        return;
    uint8_t *code = (uint8_t *)malloc(num * 4);
    uc_mem_read(uc, pc, code, num * 4);

	count = cs_disasm(handle, code, num * 4, pc, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,insn[j].op_str);
		}
		cs_free(insn, count);
	} 
	else {
		printf("ERROR: Failed to disassemble given code!\n");
	}

	cs_close(&handle);
    free(code);
	scanf("%*c");
}

// static bool hook_memalloc(uc_engine *uc, uc_mem_type type, uint64_t address,int size, int64_t value, void *user_data){
// 	printf("---------- Access error --------- \n");
// 	printf("type 0x%x\n", type );
// 	printf("address 0x%lx\n", address);
// 	printf("value 0x%lx\n", value );
// 	uint64_t sp , x9;
// 	uc_reg_read(uc,UC_ARM64_REG_X9,&x9);
// 	uc_reg_read(uc,UC_ARM64_REG_SP,&sp);
// 	printf("SP : %lx\n",sp);
// 	printf("X9 : %lx\n",x9);
	
// }

void mem_write_wrapper(uc_engine *uc , uint64_t mem , uint64_t value){
	void *val ; 
	uc_err err;

	val = &value;
	// printf("value : 0x%x\n",value);

	uc_mem_write(uc,mem,val,4);
	// if (err){
	// 	printf("Failed to uc_mem_write() return %u: %s\n",err,uc_strerror(err));
	// }
}
/*
void hexdump(uc_engine *uc ,uint64_t mem , uint32_t len){
	char *tmp = malloc(len);
	memset(tmp,0,len);
	uc_mem_read(uc , mem , tmp , len );

	printf("0x");
	for (int i = 0 ; i< len; i++){
		printf("%02x", 0xFF & tmp[i]);
	}
	printf("\n");
}
*/
void hexdump(uc_engine *uc ,uint64_t mem ){
	uint64_t r[32];
    int i = 0;
    uc_mem_read(uc, mem , &r[i] , 8);
    printf("Mem 0x%x dump : 0x%016lx ",mem , r[i]);
    printf("\n");

}

char* get_got_symbol(uc_engine *uc, FILE *elf,
					unsigned int dynmaic_file_offset,
					unsigned int vm_base ,
					unsigned int got,
					unsigned int got_members,
					unsigned int symtab,
					unsigned int strtab,
					unsigned int iter){
	

	// file offset mapping with virtual address , dynmaic file offset = 0x39000 , vm = 0x36000 , got = 0x36F58 
	// 0x39000 + 0xf58 will be the real got location in file to read 
	unsigned int got_diff_num , symtab_diff_num , strtab_diff_num , func_offset , index , st_name; 
	
	
	got_diff_num = got - vm_base ;
	symtab_diff_num = symtab - vm_base; 
	strtab_diff_num = strtab - vm_base;


	Elf64_Rela func_rela ;

	// symbol_name = dynstr + dynsym[index]->st_name 
	
	char buffer[0x100];
	char *dyn_str = strtab + strtab_diff_num ; 
	Elf64_Sym dyn_sym ;

	fseek(elf , dynmaic_file_offset + got_diff_num , SEEK_SET);
	fread(&func_rela , sizeof(func_rela) , 1, elf );
	func_offset = func_rela.r_offset ; 
	func_array[iter].got_table = func_rela.r_offset;

	index = func_rela.r_info >> 32 ;
	
	fseek(elf , dynmaic_file_offset + symtab_diff_num + sizeof(dyn_sym) * index , SEEK_SET);
	fread(&dyn_sym , sizeof(dyn_sym) , 1, elf );
	st_name = dyn_sym.st_name ; 

	
	fseek(elf, dynmaic_file_offset + strtab_diff_num + st_name  , SEEK_SET);
	int ch , i ;
	for (i = 0; (i < (sizeof(buffer)-1) &&
         ((ch = fgetc(elf)) != EOF) && (ch != '\n')); i++)
      buffer[i] = ch;
 
   	buffer[i] = '\0';
	// printf("Resolve symbol :%s\n",buffer);

	char * p = malloc(0x100);
	memcpy(p, buffer , i);

	return p ;

}
unsigned int cmn_symtab = 0;
unsigned int cmn_strtab = 0;

void resolve_dynamic(uc_engine *uc, FILE* elf, bool target_ta , unsigned int dynmaic_file_offset , unsigned int vm_base){
	
	Elf64_Dyn dyn;
	int count = 0 , sym_end = 0;
	unsigned int got  = 0 , strtab = 0, symtab = 0 , dt_hash = 0 , got_members = 0; 


	while (sym_end != 1){

		fseek(elf, dynmaic_file_offset + (sizeof(dyn)*count) , SEEK_SET);
		fread(&dyn , sizeof(dyn) , 1 , elf);
		count +=1 ;
		// printf("dtag : 0x%x\n",dyn.d_tag);
		if (dyn.d_tag == DT_HASH){
			dt_hash = dyn.d_un.d_val;
		}

		if (dyn.d_tag == DT_JMPREL){
			got = dyn.d_un.d_val;
		}
		if (dyn.d_tag == DT_SYMTAB){
			symtab = dyn.d_un.d_val;
		}
		if (dyn.d_tag == DT_STRTAB){

			strtab = dyn.d_un.d_val;
		}


		if (dyn.d_tag == NULL){
			sym_end = 1;
		}
	}
	if ( target_ta == false ){
		cmn_strtab = strtab;
		cmn_symtab = symtab; 
	}

	
	got_members = (dt_hash - got) / 0x18 ; // sizeof Elf64_Rela 
	puts("***************************");

	printf("DT_HASH : 0x%x\n",dt_hash);
	printf("GOT members : 0x%x\n", got_members);
	printf("GOT table : 0x%x\n",got);
	printf("SYMTAB : 0x%x\n",symtab);
	printf("STRTAB : 0x%x\n",strtab);
	
	puts("***************************");

	char *func_symbol;

	if (target_ta == true){
		for (int i = 0 ; i < 0x40 ; i++){
			func_symbol = get_got_symbol(uc, elf, dynmaic_file_offset, vm_base , got , got_members , symtab , strtab ,i);
			func_array[i].func_name = func_symbol;
			got = got + 0x18 ; // Elf64_Rela size
			//fix_got(func_array[i].func_name);
			// printf("%s : 0x%x\n",func_array[i].func_name , func_array[i].got_table);
			
			// libcmnlib_mappfunc(uc , func_symbol);
		}
	}
}


void getfunction_addr(uc_engine *uc, FILE* elf, 
					unsigned int dynmaic_file_offset,
					unsigned int symtab, unsigned int strtab,
					unsigned int vm_base,
					unsigned int iter){

	unsigned int got_diff_num , symtab_diff_num , strtab_diff_num , func_offset , index , st_name; 
	symtab_diff_num = symtab - vm_base; 
	strtab_diff_num = strtab - vm_base;

	// symbol_name = dynstr + dynsym[index]->st_name 
	char buffer[0x100];
	char *dyn_str = strtab + strtab_diff_num ; 
	Elf64_Sym dyn_sym ;
	
	fseek(elf , dynmaic_file_offset + symtab_diff_num + sizeof(dyn_sym) * iter , SEEK_SET);
	fread(&dyn_sym , sizeof(dyn_sym) , 1, elf );
	st_name = dyn_sym.st_name ; 
	cmn_array[iter].func_value = dyn_sym.st_value;

	
	fseek(elf, dynmaic_file_offset + strtab_diff_num + st_name  , SEEK_SET);
	int ch , i ;
	for (i = 0; (i < (sizeof(buffer)-1) &&
         ((ch = fgetc(elf)) != EOF) && (ch != '\n')); i++)
      buffer[i] = ch;
 
   	buffer[i] = '\0';

	// printf("Resolve symbol :%s\n",buffer);

	char * p = malloc(0x100);
	memcpy(p, buffer , i);
	cmn_array[iter].func_name = p;

	return p ;

}

void parse_cmnlib(uc_engine* uc, char * cmnlib){
	Elf64_Ehdr ehdr ;
	Elf64_Phdr phdr ; 
	uc_err err;

	FILE * elf = fopen(cmnlib,"rb");
	
	fread(&ehdr , sizeof(ehdr) , 1 , elf);
	char segment_data[0x100000];
	unsigned int segment_offset , segment_align_size , segment_size , segment_map_addr , dynamic_section  , cmn_symtab_size; 
	for (int i = 0 ; i < ehdr.e_phnum ; i++){

		fseek(elf , ehdr.e_phoff + (sizeof(phdr) * i) , SEEK_SET);

		fread(&phdr , sizeof(phdr) , 1, elf);
		
		if (phdr.p_type == PT_NULL){
			continue;
		}
		char *func_symbol;
		if (phdr.p_type == PT_DYNAMIC){
			dynamic_section = phdr.p_offset ; 
			// 0x39000 file offset 
			printf("Find libcmnlib dynamic section offset : 0x%x\n",dynamic_section);
			resolve_dynamic(uc, elf, false, dynamic_section ,phdr.p_vaddr);
			printf("cmn_symtab : 0x%x\n",cmn_symtab);
			printf("cmn_strtab : 0x%x\n",cmn_strtab);
			printf("cmn_dyn file offset : 0x%x\n",dynamic_section);
			printf("cmn_dyn va : 0x%x\n",phdr.p_vaddr);

			cmn_symtab_size = (cmn_strtab - cmn_symtab)/0x18;

			if (sizeof(cmn_array)/sizeof(struct cmnfunc_info) < cmn_symtab_size){
				puts("Modify cmn_array size !");
			}
			for (int i = 0; i< cmn_symtab_size ; i++){
				getfunction_addr(uc, elf, dynamic_section ,cmn_symtab, cmn_strtab , phdr.p_vaddr ,i);
				// printf("%s : 0x%x\n", cmn_array[i].func_name,cmn_array[i].func_value);
			}
		
		}
		segment_offset = phdr.p_offset ; 

		segment_size  = phdr.p_filesz ; 
		if ( segment_size % 0x1000 != 0 ){
			segment_align_size = segment_size + ( 0x1000 - segment_size % 0x1000 );
			printf("Segment alignment size : 0x%x\n", segment_align_size);
		}
		// cmn text segment offset (user defined  -> In order not same with TA text base !)
		phdr.p_vaddr = phdr.p_vaddr + libcmnlib_text_offset;
		segment_map_addr = phdr.p_vaddr ;
		
		// if (phdr.p_vaddr == 0){ 
		// 	segment_map_addr = phdr.p_vaddr + libcmnlib_text_offset;
		// }else{
		// 	segment_map_addr = phdr.p_vaddr ; 
		// }

		// printf("Before : 0x%x , After : 0x%x",tmp_map_addr,phdr.p_vaddr);
		if (tmp_map_addr == phdr.p_vaddr){
			if (tmp_map_addr_size > phdr.p_filesz || tmp_memseg_size == 0){
				printf("Init state or same memory remmaped encounter !\n");
			}else{
				printf("Unmap addr : 0x%x, size : 0x%x\n", tmp_map_addr, tmp_memseg_size);
				err = uc_mem_unmap(uc, tmp_map_addr, tmp_memseg_size);
				if (err){
					printf("Failed to uc_mem_unmap() return %u: %s\n",err,uc_strerror(err));
				}
			}
		}

		fseek( elf , segment_offset , SEEK_SET );	
		fread(segment_data , segment_align_size , 1 , elf);
		err = uc_mem_map(uc , segment_map_addr , segment_align_size , UC_PROT_ALL );
		if (err){
			printf("Failed to uc_mem_map() return %u: %s\n",err,uc_strerror(err));
		}else{
			if (err == UC_ERR_OK){
				printf("memory 0x%x ~ memory 0x%x map success\n ",segment_map_addr,segment_map_addr+segment_align_size);
			}
		}
		err = uc_mem_write(uc , segment_map_addr , segment_data , segment_align_size );	
		if (err){
			printf("Failed to uc_mem_write() return %u: %s\n",err,uc_strerror(err));
		}
		printf("Mapping segment offset 0x%x\t\t Segment size 0x%x\t Segment map addr 0x%x\t\n",segment_offset , segment_size , segment_map_addr); 
		tmp_memseg_size = segment_align_size;
		tmp_map_addr = segment_map_addr ;
		tmp_map_addr_size = phdr.p_filesz;
		
	}

}

void fix_got(uc_engine *uc){
	hexdump(uc, func_array[0].got_table );

	for (int i = 0 ; i< sizeof(func_array)/sizeof(struct func_info); i++){
		for (int j = 0 ; j < sizeof(cmn_array)/sizeof(struct cmnfunc_info); j++){
			if (func_array[i].func_name == NULL) break;

			if (!strcmp(func_array[i].func_name, cmn_array[j].func_name)){
				//printf("%s got : 0x%x -> relocate to  0x%x\n",func_array[i].func_name,func_array[i].got_table ,cmn_array[j].func_value + libcmnlib_text_offset);
				mem_write_wrapper(uc, func_array[i].got_table, cmn_array[j].func_value + libcmnlib_text_offset);
				// scanf("%*c");
				break;
			}


		}
	}
	//debug to verify fix or not;
	hexdump(uc, func_array[0].got_table );


}

void parse_header(uc_engine * uc , char * ta_file){
	
	parse_cmnlib(uc,"./libcmnlib.so");

	tmp_memseg_size , tmp_map_addr, tmp_map_addr_size = 0;


	Elf64_Ehdr ehdr ;
	Elf64_Phdr phdr ; 

	FILE * elf = fopen(ta_file,"rb");
	
	fread(&ehdr , sizeof(ehdr) , 1 , elf);
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) == 0) {
		puts("***************************");
    	puts("Valid elf file");
		printf("Program header offset : %lx\n",ehdr.e_phoff);
		printf("Program header entries : %d\n",ehdr.e_phnum );
		puts("***************************");

	}

	uc_err err;
	char segment_data[0x100000];
	unsigned int segment_offset , segment_align_size , segment_size , segment_map_addr , dynamic_section  ; 
	for (int i = 0 ; i < ehdr.e_phnum ; i++){

		fseek(elf , ehdr.e_phoff + (sizeof(phdr) * i) , SEEK_SET);

		fread(&phdr , sizeof(phdr) , 1, elf);
		
		if (phdr.p_type == PT_NULL){
			continue;
		}

		if (phdr.p_type == PT_DYNAMIC){
			dynamic_section = phdr.p_offset ; 
			// 0x39000 file offset 
			printf("Find dynamic section offset : 0x%x\n",dynamic_section);
			resolve_dynamic(uc , elf , true ,dynamic_section ,phdr.p_vaddr);
		}

		segment_offset = phdr.p_offset ; 
		segment_size  = phdr.p_filesz ; 
		if ( segment_size % 0x1000 != 0 ){
			segment_align_size = segment_size + ( 0x1000 - segment_size % 0x1000 );
			printf("Segment alignment size : 0x%x\n", segment_align_size);
		}
		segment_map_addr = phdr.p_vaddr ; 

		//check remmaped memory
		if (tmp_map_addr == phdr.p_vaddr){
			if (tmp_map_addr_size > phdr.p_filesz){
				printf("Init state or same memory remmaped encounter !\n");
			}else{
				printf("Remmaped addr : 0x%x , size : 0x%x\n",tmp_map_addr, tmp_memseg_size);
				err = uc_mem_unmap(uc, tmp_map_addr, tmp_memseg_size);
				if (err){
					printf("Failed to uc_mem_unmap() return %u: %s\n",err,uc_strerror(err));
				}
			}
		}

		fseek( elf , segment_offset , SEEK_SET );	
		fread(segment_data , segment_align_size , 1 , elf);
		err = uc_mem_map(uc , segment_map_addr , segment_align_size , UC_PROT_ALL );
		if (err){
			printf("Failed to uc_mem_map() return %u: %s\n",err,uc_strerror(err));
		}
		err = uc_mem_write(uc , segment_map_addr , segment_data , segment_align_size );	
		if (err){
			printf("Failed to uc_mem_write() return %u: %s\n",err,uc_strerror(err));
		}
		printf("Mapping segment offset 0x%x\t\t Segment size 0x%x\t Segment map addr 0x%x\t\n",segment_offset , segment_size , segment_map_addr); 
		tmp_memseg_size = segment_align_size;
		tmp_map_addr = phdr.p_vaddr ;
		tmp_map_addr_size = phdr.p_filesz;

	}

	//map stack address

	fix_got(uc);
	uint64_t stack_address = 0x100000;
	uint64_t stack_size = 0x300000;
	uint64_t sp ;
	err = uc_mem_map(uc, stack_address, stack_size, UC_PROT_ALL);
	if (err){
		printf("Failed to uc_mem_map() return %u: %s\n", err, uc_strerror(err));
	}
	sp = stack_address +  (stack_size / 2) ;
	uc_reg_write(uc, UC_ARM64_REG_SP, &sp);
	uc_reg_read(uc,UC_ARM64_REG_SP,&sp);
	printf("SP : %lx\n",sp);
	


	// scanf("%*c");
}

