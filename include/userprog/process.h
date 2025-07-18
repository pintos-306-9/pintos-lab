#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#define MAX_ARGS 64

#include "threads/thread.h"

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);
int process_allocate_fd(struct file *file);
void process_close_file(int fd);
struct file *process_get_file(int fd);
void process_remove_file(int fd);

#endif /* userprog/process.h */
