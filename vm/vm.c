/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"

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
	list_init(&frame_table);
    lock_init(&frame_table_lock);
}

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
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
	}
err:
	return false;
}

// UNUSED의 경우 한번도 사용하지 않은 변수에 대해서 컴파일시 경고를 주지 말라는 매크로.
// VA에 대한 페이지 주소를 찾으면 페이지 주소를 반환, 몾 찾으면 NULL을 반환 -> 세그멘테이션 폴트, 또는 스택 확장의 경우로 연결.
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	lock_acquire(&spt->spt_lock);
	struct page page; // 임시 변수 생성
	struct hash_elem *e; // 반환 값, 즉 페이지의 포인터 변수를 받아야 해서.

	page.va = pg_round_down(va); // 페이지의 시작 주소로 변경, 페이지의 중간 값이 VA로 들어올 수 있기 때문에 페이지의 시작 주소로 바꿔야 한다.
	e = hash_find(&spt->spt_hash, &page.hash_elem); // SPT의 해시와, 키 즉 찾고자 하는 값을 넘긴다.
	
	if (e != NULL) {
        // 해시 테이블에서 요소를 찾음
        // hash_entry를 사용해서 e가 속한 전체 struct page의 주소를 계산하여 반환
        lock_release(&spt->spt_lock);
        return hash_entry(e, struct page, hash_elem);
    } else {
        // 못 찾음, 세그멘테이션 폴트, 또는 스택 확장의 경우.
        lock_release(&spt->spt_lock);
        return NULL;
    }
}


bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
    lock_acquire(&spt->spt_lock);

    struct hash_elem *result = hash_insert(&spt->spt_hash, &page->hash_elem);
	// hash_insert는 성공시 NULL반환

	if (result == NULL)
	{
		lock_release(&spt->spt_lock);
		return true;
	} else
	{
		lock_release(&spt->spt_lock);
		return false;
	}
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
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
vm_get_frame(void)
{
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	void *kva = palloc_get_page(PAL_USER); // user pool에서 새로운 physical page를 가져온다.

	if (kva == NULL) // page 할당 실패
	{
		struct frame *victim = vm_evict_frame();
		victim->page = NULL;
		return victim;
	}

	frame = (struct frame *)malloc(sizeof(struct frame)); // 프레임 할당
	frame->kva = kva;									  // 프레임 멤버 초기화
	frame->page = NULL;

	lock_acquire(&frame_table_lock);
	list_push_back(&frame_table, &frame->frame_elem);
	lock_release(&frame_table_lock);
	ASSERT(frame != NULL);
	ASSERT(frame->page == NULL);
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
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

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
vm_claim_page (void *va) {
	struct page *page = NULL;

	page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL)  
        return false;
	return vm_do_claim_page (page);
}

static bool vm_do_claim_page(struct page *page) {
    //페이지를 담을 물리 프레임을 할당
    struct frame *frame = vm_get_frame();
    if (frame == NULL) {
        return false;
    }

    frame->page = page;
    page->frame = frame;

    // 데이터를 프레임에 로드
    if (!swap_in(page, frame->kva)) {
        // 데이터 로딩에 실패하면, 자원을 정리하고 실패
        frame->page = NULL;
        page->frame = NULL;
        vm_free_frame(frame);
        return false;
    }

    // 페이지 테이블 맵핑
    if (!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
        // 매핑에 실패하는 경우.
        frame->page = NULL;
        page->frame = NULL;
        return false;
    }

    return true; 
}

void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
    // 해시 초기화, 앞으로 해시 값을 어떤 방법으로 찾고, 어떤 방식으로 비교할지 지정해두는 것, 해시 구조체로 넘어간다.
    hash_init(spt, page_hash, page_less, NULL);
    lock_init(&spt->spt_lock); // 락을 초기화/
}

unsigned // 앞으로 페이지에 대한 elem 값을 넘기면 해당 elem이 있는 구조체의 VA값을 키 값으로 반환한다.
page_hash(const struct hash_elem *p_, void *aux UNUSED) 
{
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

// 해시 값을 찾을 때 비교가 필요하다. 즉 비교용 함수.
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
const struct page *a = hash_entry(a_, struct page, hash_elem);
const struct page *b = hash_entry(b_, struct page, hash_elem);
return a->va < b->va;
}


/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
