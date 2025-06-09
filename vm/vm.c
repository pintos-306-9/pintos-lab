/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "userprog/process.h"

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
//지연 로딩을 위해서 쓰는 함수, 즉 프로세스 VM을 세팅할 때 SPT에 uninit의 상태로 놓기 위한 함수.
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable, vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {

		struct page *p = (struct page *)malloc(sizeof(struct page));
        if (p == NULL) {
            goto err; // malloc 실패 시 err로 이동
        }
		// 초기화 함수를 가져오자.
		bool (*page_initializer)(struct page *, enum vm_type, void *);

		switch (VM_TYPE(type))
        {
        case VM_ANON:
            page_initializer = anon_initializer;
            break;
        case VM_FILE:
            page_initializer = file_backed_initializer;
            break;
        default:
            goto err;
        }

        // 3) "uninit" 타입의 페이지로 초기화한다.
        uninit_new(p, upage, init, type, aux, page_initializer);

        // 필드 수정은 uninit_new를 호출한 이후에 해야 한다.
        p->writable = writable;
		if (!spt_insert_page(spt, p)) {
            free(p); 
            goto err;
        }

        return true; 
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
vm_stack_growth (void *addr) {
    vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present)
{
    struct supplemental_page_table *spt = &thread_current()->spt;

    if (addr == NULL)
        return false;

    if (is_kernel_vaddr(addr))
        return false;

    if (not_present) // 접근한 메모리의 physical page가 존재하지 않은 경우
    {
        void *rsp = user ? f->rsp : thread_current()->rsp_stack;

        // 스택 확장 조건 검사
        bool stack_growth = 
            ((USER_STACK - (1 << 20) <= rsp - 8 && addr == rsp - 8) ||  // PUSH 계열
             (USER_STACK - (1 << 20) <= rsp && addr >= rsp)) &&         // 일반적인 접근
            addr <= USER_STACK;

        if (stack_growth) {
            vm_stack_growth(addr);
        }

        // 반드시 다시 페이지를 조회해야 새로 확장된 페이지도 인식됨
        struct page *page = spt_find_page(spt, addr);
        if (page == NULL)
            return false;

        if (write && !page->writable) // 쓰기 권한 없음
            return false;

        return vm_do_claim_page(page);
    }

    return false;
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

bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
    struct hash_iterator i;
    hash_first(&i, &src->spt_hash);
    while (hash_next(&i)) {
        struct page *src_page =
            hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type type = src_page->operations->type;
        void *upage = src_page->va;
        bool writable = src_page->writable;

        if (type == VM_UNINIT) {
            vm_initializer *init = src_page->uninit.init;
            void *aux = src_page->uninit.aux;

            // 🚨 file-backed일 경우, file_reopen 필수
            if (src_page->uninit.type == VM_FILE) {
                struct lazy_load_arg *src_aux = aux;
                struct lazy_load_arg *dst_aux =
                    malloc(sizeof(struct lazy_load_arg));
                memcpy(dst_aux, src_aux, sizeof(struct lazy_load_arg));
                dst_aux->file = file_reopen(src_aux->file); // 중요!
                aux = dst_aux;
            }

            if (!vm_alloc_page_with_initializer(src_page->uninit.type, upage,
                                                writable, init, aux))
                return false;
            continue;
        }

        // file-backed이지만 UNINIT이 아닌 경우는 거의 없으나 안전하게 처리
        if (type == VM_FILE) {
            struct lazy_load_arg *file_aux =
                malloc(sizeof(struct lazy_load_arg));
            file_aux->file = src_page->file.file;
            file_aux->ofs = src_page->file.ofs;
            file_aux->read_bytes = src_page->file.read_bytes;
            file_aux->zero_bytes = src_page->file.zero_bytes;
            if (!vm_alloc_page_with_initializer(type, upage, writable, NULL,
                                                file_aux))
                return false;
            struct page *file_page = spt_find_page(dst, upage);
            file_backed_initializer(file_page, type, NULL);
            file_page->frame = src_page->frame;
            pml4_set_page(thread_current()->pml4, file_page->va,
                          src_page->frame->kva, src_page->writable);
            continue;
        }

        // 나머지 페이지 (anon 등)
        if (!vm_alloc_page(type, upage, writable))
            return false;
        if (!vm_claim_page(upage))
            return false;

        struct page *dst_page = spt_find_page(dst, upage);
        memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
    }
    return true;
}

/* Free the resource hold by the supplemental page table */
// SPT가 보유하고 있던 모든 리소스를 해제하는 함수 (process_exit(),
// process_cleanup()에서 호출)
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    // todo: 페이지 항목들을 순회하며 테이블 내의 페이지들에 대해
    // destroy(page)를 호출
    hash_clear(&spt->spt_hash, hash_page_destroy); // 해시 테이블의 모든 요소를 제거

    /** hash_destroy가 아닌 hash_clear를 사용해야 하는 이유
     * 여기서 hash_destroy 함수를 사용하면 hash가 사용하던 메모리(hash->bucket)
     * 자체도 반환한다. process가 실행될 때 hash table을 생성한 이후에
     * process_clean()이 호출되는데, 이때는 hash table은 남겨두고 안의 요소들만
     * 제거되어야 한다. 따라서, hash의 요소들만 제거하는 hash_clear를 사용해야
     * 한다.
     */

    // todo🚨: 모든 수정된 내용을 스토리지에 기록
}

void hash_page_destroy(struct hash_elem *e, void *aux) {
    struct page *page = hash_entry(e, struct page, hash_elem);
    destroy(page);
    free(page);
}
