#include <stdio.h>
#include <stdlib.h>
#include <unicorn/unicorn.h>
#include <string.h>


char * ascii_read_string(uc_engine *uc ,uint64_t address){
    char *string  = malloc(0x40) ;
    memset(string,0,sizeof(string));
    char x; 
    //     uc_mem_read(uc, pc, code, num * 4);
    while(1){
        uc_mem_read(uc, address , &x , 1);
        address +=1;
        if ( x == '\0' ){            
            return string;
        }
        strncat(string,&x,1);
    }

}

// Example for hooking qsee_log in libcmnlib.so
void qsee_log(uc_engine *uc){
    uint64_t  lr , X2 ,X3 ;
    char * error_string;
    uc_reg_read(uc, UC_ARM64_REG_X2 , &X2);
    error_string = ascii_read_string(uc , X2);

    uc_reg_read(uc,UC_ARM64_REG_X3, &X3);

    uc_reg_read(uc,UC_ARM64_REG_LR, &lr);
	printf("Error at function %s line %ld maked\n", error_string , X3 );
    uc_reg_write(uc,UC_ARM64_REG_PC,&lr);
    

}



void hook_cmnlib(uc_engine *uc , uint64_t pc){
    if ( pc == 0x0){
        qsee_log(uc);
    }

}
