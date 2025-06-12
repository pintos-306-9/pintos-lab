/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

/* page의 va를 해싱하는 함수 */
uint64_t page_hash (const struct hash_elem *e, void *aux);

/* va 기준으로 순서 비교 */
bool page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);


/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

// void init_load_field(struct load_field* load_field, struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable){
// 	load_field->file = file;
// 	load_field->ofs = ofs;
// 	load_field->upage = upage;
// 	load_field->read_bytes = read_bytes;
// 	load_field->zero_bytes = zero_bytes;
// 	load_field->writable = writable;
// }

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page* p;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		// 페이지를 하나 만들어주고 vm type에 맞는 initializer를 인자로 갖는 uninit_new함수를 호출한다.
		// palloc_get_page()는 1page(4KB)를, malloc(sizeof(struct page))는 page구조체 만큼의 공간을 할당해준다는 차이만 있을 뿐.. 두개 중 뭘 쓰든 상관 없나? 페이지 구조체를 생성하고자하는 상황이므로 malloc이 더 적합하다고 판단되어 malloc 사용함

		// struct page* p = palloc_get_page(PAL_USER);
		
		p = (struct page*)malloc(sizeof(struct page));
		if(p == NULL) 
			return false;
	}

	bool(*page_initializer)(struct page*, enum vm_type, void *kva);
		
		switch(VM_TYPE(type)){
			case VM_ANON:
			// uninit_new(p, p->va, init, type, NULL, anon_initializer);
			// uninit_new(p, upage, init, type, aux, anon_initializer);
			page_initializer = anon_initializer;
			
			break;
			case VM_FILE:
			// uninit_new(p, p->va, init, type, NULL, file_backed_initializer);
			// uninit_new(p, upage, init, type, aux, file_backed_initializer);	
			page_initializer = file_backed_initializer;
			break;			
		}	

		uninit_new(p, upage, init, type, aux, page_initializer);

		p->writable = writable;

		/* TODO: Insert the page into the spt. */
		int result = spt_insert_page(spt, p);
		// printf("result: %d", result);
		return result;
		// return true;
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
//spt가 va에 해당하는 page를 가지고 있는지 찾아서 리턴, 못 찾으면 NULL 리턴
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page p;
	struct hash_elem *e;
	
	/* TODO: Fill this function. */
	//hash table 탐색 : dummy.hash_elem주소를 넣으면 해시 테이블 내부에서 같은 va를 가진 요소를 찾아줌
	p.va = pg_round_down(va); //검색할 키를 정렬된 값으로 세팅
	e = hash_find(&spt->spt_hash, &p.hash_elem); //해시 테이블, 검색용 포인터를 넘김

	// 지워도 되는 부분
	// struct hash_iterator *i;
	// hash_first(i, &spt->spt_hash);
	// struct hash_elem *elem = hash_cur(i);
	// struct page *page = hash_entry(elem, struct page, hash_elem);
	// printf("elem = %p", elem);
	// printf("page elem = %p",page->hash_elem);

	// 지워도 되는 부분

	if(e == NULL){
		// printf("nulllllllll");
		return NULL;
	}

	//hash_elem 포인터 -> struct page 포인터로 변환
	return hash_entry(e, struct page, hash_elem);	
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	bool succ = false;

	/* TODO: Fill this function. */
	//va에 대응하는 struct page의 hash_elem을 spt의 hash table에 등록
	if(spt_find_page(spt, page->va) == NULL){
		hash_insert(&spt->spt_hash, &page->hash_elem);
		succ = true;
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	struct hash_elem *e = hash_find(&spt->spt_hash, &page->hash_elem);
	if(e == NULL){
		return false;
	}
	hash_delete(&spt->spt_hash, e);
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	/* TODO: Fill this function. */
	/*
	유저 메모리 풀에서 palloc_get_page()로 새로운 물리 프레임 할당받기
	1. free 프레임인지 확인해야 함
	2. free 프레임이 없다면 특정 프레임을 디스크로 쫓아내 free로 만들어주고 그 프레임을 가져와야 함
		디스크로 쫓아낼 프레임을 고르는 방법은 페이지 테이블의 accessed, dirty 비트를 참조하는 것이다.
		프레임을 쫓아냈다면 그 프레임을 참조하는 모든 페이지 테이블에서 참조를 제거한다. 공유되지 않았다면 해당 프레임을 참조하는 페이지는 항상 한 개만 존재해야 한다.
		필요하다면 쫓아낸 페이지를 파일 시스템이나 스왑에 write해야 함
	3. 스왑 영역 마저 꽉 차있다면 커널 패닉을 발생시킴 <-???
	*/
	//free된 frame인지 구현해야됨
	
	/* 프레임 정보를 담을 공간 할당 */
	struct frame* frame = (struct frame*)malloc(sizeof(struct frame));
	
	/* 물리 메모리에 프레임 할당 */
	// void* kva = palloc_get_page(PAL_USER);
	uint64_t *kva = palloc_get_multiple(PAL_USER, 1);
	if(kva == NULL){
		PANIC("No memory.");
	}

	/* frame과 va를 매핑 */
	frame->kva = kva;
	frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {

	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;


	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	/*
	1. 접근한 주소가 유효한지 확인 (done)
			주소가 NULL이거나 KERN_BASE보다 크면 유저 프로그램이 접근할 수 없는 영역이므로 false 리턴
	2. spt에서 해당 가상 주소에 해당하는 page 구조체가 있는지 확인 (done)
			현재 spt에서 addr에 해당하는 page가 있는지 찾기
			아직 없다면 lazy load되지 않은 영역이거나 stack 확장이 필요할 수 있다
	3. stack growth 가능성 확인 
			접근한 주소가 스택 포인터 근처이고, 사용자 영역 내에 있다면 스택 확장 허용
			vm_stack_growth()함수로 새 page를 spt에 등록하고 다시 찾음
	4. 정상적인 page를 찾았으면 claim 요청
			page가 spt에 존재하고 접근도 유효하다가 판단되었으므로 해당 page를 메모리에 올리기 위한 claim작업 진행 (frame 할당 + 파일/anon페이지 내용 로딩)
	*/

	// if(addr == NULL || addr > KERN_BASE)
	// 	return false;
	
	//페이지를 찾고
	// struct page* page = spt_find_page(&spt->spt_hash, &addr);
	struct page* page = spt_find_page(spt, addr);

	if(page == NULL){ //아직 페이지가 없으면 유효하지 않은 접근
		//todo: 스택의 경우 페이지를 만들어준다
		// if(스택을 자동으로 확장시켜줘야 하는 경우){
			// return vm_alloc_page_with_initializer(VM_ANON, addr, 1, anon_initializer, NULL);
		// }
		// printf("NULL!!!!!!!!!");
		return false;
	} 
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	if(page == NULL) return false;
	// if(page->frame != NULL) return true;
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	/*
	인자로 주어진 page에 물리 프레임을 할당
	1. vm_get_frame()을 호출하여 프레임 하나를 할당받기
	2. mmu 세팅하기
		va-pa 매핑 정보를 page table에 추가하기: threads/mmu.c에 있는 함수 사용하기
	3. 1, 2번 연산이 성공했으면 true 반환, 그렇지 않으면 false 반환
	*/

	if(!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)){
		return false;
	}

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);
}

uint64_t page_hash (const struct hash_elem *e, void *aux){
	const struct page* p = hash_entry(e, struct page, hash_elem);
	return hash_bytes(&p->va, sizeof(p->va));
}

bool page_less (const struct hash_elem *a,
           const struct hash_elem *b,
           void *aux UNUSED) {
    const struct page *p_a = hash_entry (a, struct page, hash_elem);
    const struct page *p_b = hash_entry (b, struct page, hash_elem);
    return p_a->va < p_b->va;
}
 
/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	
}

void hash_destructor (struct hash_elem *e, void *aux){
	//hash_elem이 포함된 페이지를 free시키기
	struct page* p = hash_entry(e, struct page, hash_elem);
	//page free 시키기
	// free(p);
	// hash_delete(&thread_current()->spt, e);
	spt_remove_page(&thread_current()->spt, p);
	
}
/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(spt, hash_destructor);
}

