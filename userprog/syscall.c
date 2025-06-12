#include "userprog/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "vm/vm.h"
#include <lib/stdio.h>
#include <list.h>
#include <syscall-nr.h>

#include "filesys/directory.h"
#include "filesys/fat.h"
#include "filesys/inode.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);
bool validate_user_address(void *address);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

struct lock file_rw_lock;

void syscall_init(void) {
    lock_init(&file_rw_lock);
    write_msr(MSR_STAR,
              ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK,
              FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

void syscall_handler(struct intr_frame *f UNUSED) {
    // The order of the arguments -> %rdi, %rsi, %rdx, %r10, %r8, %r9
    // return value is f->rax
    // printf("[DEBUG] syscall_handler invoked! rax=%lld\n", f->R.rax);

    uint64_t syscall_num = f->R.rax;

    switch (syscall_num) {
    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;

    case SYS_EXIT:
        exit(f->R.rdi);
        break;

    case SYS_HALT:
        halt();
        break;

    case SYS_CREATE:
        f->R.rax = create(f->R.rdi, f->R.rsi);
        break;

    case SYS_OPEN:
        f->R.rax = open(f->R.rdi);
        break;

    case SYS_CLOSE:
        close(f->R.rdi);
        break;

    case SYS_FILESIZE:
        f->R.rax = filesize(f->R.rdi);
        break;

    case SYS_READ:
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;

    case SYS_FORK:
        f->R.rax = fork(f->R.rdi, f);
        break;

    case SYS_WAIT:
        f->R.rax = wait(f->R.rdi);
        break;

    case SYS_EXEC:
        if (exec(f->R.rdi) == -1) {
            exit(-1);
        }
        break;

    case SYS_SEEK:
        seek(f->R.rdi, f->R.rsi);
        break;

    case SYS_REMOVE:
        f->R.rax = remove(f->R.rdi);
        break;

    default:
        printf("Unknown syscall number: %lld\n", syscall_num);
        thread_exit();
    }
}

/* ---------------validator---------------- */

bool validate_user_address(void *address) {
    if (!is_user_vaddr(address)
        || pml4_get_page(thread_current()->pml4, address) == NULL){
        return false;
    }
    return true;
}

bool validate_kernel_address(void *address) {
    if (!is_kernel_vaddr(address)) {
        return false;
    }
    return true;
}

bool validate_fd(int fd) { return !(fd < 0 || fd >= FD_MAX); }

/* ---------------system call---------------*/

int write(int fd, const void *buffer, unsigned size) {
    if (!validate_user_address(buffer)) {
        exit(-1);
    }
    if (!validate_fd(fd)) {
        return -1;
    }

    int write_result;
    struct file *fileobj = process_get_file(fd);
    if (fileobj == NULL) {
        return -1;
    }
    struct thread *cur = thread_current();
    if (fd == 1) {
        putbuf(buffer, size);
        write_result = size;
    } else if (fd == 0) {
        write_result = -1;
    } else {
        lock_acquire(&file_rw_lock);
        write_result = file_write(fileobj, buffer, size);
        lock_release(&file_rw_lock);
    }
    return write_result;
}

void exit(int status) {
    struct thread *cur = thread_current();
    cur->exit_status = status;
    printf("%s: exit(%d)\n", thread_name(), status);
    thread_exit();
}

void halt(void) { power_off(); }

bool create(const char *file, unsigned initial_size) {
    if (!validate_user_address(file)) {
        exit(-1);
    }
    bool result = filesys_create(file, initial_size);

    return result;
}

int open(const char *file) {
    if (!validate_user_address(file)) {
        exit(-1);
    }

    struct file *opened = filesys_open(file);

    if (opened == NULL) {
        return -1;
    }
    int fd = process_allocate_fd(opened);

    if (fd == -1) {
        file_close(opened);
    }
    return fd;
}

void close(int fd) {
    // struct file *fileobj = process_get_file(fd);
    // if (fileobj == NULL)
    //     return;

    // struct thread *cur = thread_current();

    // // fd = 0 : stdin, 1 : stdout - thread.c/thread_create 참고
    // if (fd == 0 || fileobj == 1) {
    //     cur->stdin_count--;
    // } else if (fd == 1 || fileobj == 2) {
    //     cur->stdout_count--;
    // }

    // process_remove_file(fd);
    // if (fd <= 1 || fileobj <= 2)
    //     return;
    process_remove_file(fd);
}

int filesize(int fd) {

    if (!validate_fd(fd)) {
        return -1;
    }

    struct file *f = process_get_file(fd);

    if (f == NULL) {
        return -1;
    }

    return file_length(f);
}

int read(int fd, void *buffer, unsigned size) {
    if (!validate_user_address(buffer)) {
        exit(-1);
    }

    if (!validate_fd(fd)) {
        return -1;
    }

    int read_result;
    struct thread *cur = thread_current();
    struct file *file_fd = process_get_file(fd);
    if (file_fd == NULL) {
        return -1;
    }
    if (fd == 0) {
        int i;
        unsigned char *buf = buffer;
        for (i = 0; i < size; i++) {
            char c = input_getc();
            *buf++ = c;
            if (c == '\0') {
                break;
            }
        }
        read_result = i;
    } else if (fd == 1) {
        read_result = -1;
    } else {
        lock_acquire(&file_rw_lock);
        read_result = file_read(file_fd, buffer, size);
        lock_release(&file_rw_lock);
    }
    return read_result;
}

tid_t fork(const char *thread_name, struct intr_frame *f) {
    if (!validate_user_address(thread_name)) {
        exit(-1);
    }
    return process_fork(thread_name, f);
}

int wait(pid_t pid) { return process_wait(pid); }

int exec(const char *cmd_line) {
    if (!validate_user_address(cmd_line)) {
        exit(-1);
    }

    int file_size = strlen(cmd_line) + 1;
    char *cmd_copy = palloc_get_page(PAL_ZERO);
    if (cmd_copy == NULL) {
        exit(-1);
    }
    strlcpy(cmd_copy, cmd_line, file_size);

    if (process_exec(cmd_copy) == -1) {
        return -1;
    }
    NOT_REACHED();
    return 0;
}

void seek(int fd, unsigned position) {
    if (fd <= 1) { // 0: 표준입력, 1: 표준 출력
        return;
    }

    struct file *f = process_get_file(fd);
    file_seek(f, position);
}

bool remove(const char *file_name) {
    if (!validate_user_address(file_name)) {
        exit(-1);
    }
    return filesys_remove(file_name);
}

/*------------ helper function-----------*/
