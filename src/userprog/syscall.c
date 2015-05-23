#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

struct lock sysLock;
static void syscall_handler (struct intr_frame *);
static void check_valid_buffer(const void * one, int size);
static bool verify_user (const void *uaddr);
static inline bool get_user (uint8_t *dst, const uint8_t *usrc);
static char * copy_in_string (const char *us);
static void copy_in (void *dst_, const void *usrc_, size_t size);
static void halt (void);
static tid_t exec (const char *cmd_line);
static int wait (tid_t pid);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static void close (int fd);
static unsigned tell (int fd);
static void seek (int fd, unsigned position);
static int write (int fd, const void *buffer, unsigned size);
static int read (int fd, void *buffer, unsigned size);
static int filesize (int fd);
static int open (const char *file);
struct list_elem* get_file(int fd);
static int get_kernel_ptr(void *uaddr);

void
syscall_init (void) 
{
	lock_init(&sysLock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
	unsigned callNum;
	int args[3];

	if (!verify_user(f->esp) || f->esp < (void *) 0x08048000) {
		exit(-1);
	}

	// GET SYSCALL NUMBER
	copy_in(&callNum, f->esp, sizeof callNum);


	switch(callNum)
	{
		case SYS_HALT:
		{
			halt();
			break;
		}
		case SYS_EXIT:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			exit(args[0]);
			break;
		}
		case SYS_EXEC:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			if (!verify_user((const void *)args[0])) {
				exit(-1);
			}
			char *str = copy_in_string((const char *)args[0]);
			f->eax = exec(str);
			palloc_free_page(str);
			break;
		}
		case SYS_WAIT:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			f->eax = wait(args[0]);
			break;
		}
		case SYS_CREATE:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args *2);
			check_valid_buffer((void *) args[0], (unsigned) args[1]);
			int test = get_kernel_ptr((void *) args[0]);
			f->eax = create((const char *) test, (unsigned) args[1]);
			break;
		}
		case SYS_REMOVE:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			check_valid_buffer((void *) args[0], 0);
			f->eax = remove((const char *) args[0]);
			break;
		}
		case SYS_OPEN:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			check_valid_buffer((void *) args[0], 0);
			int test = get_kernel_ptr((void *) args[0]);
			f->eax = open((const char *) test);
			break;
		}
		case SYS_FILESIZE:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			f->eax = filesize(args[0]);
			break;
		}
		case SYS_READ:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 3);
			check_valid_buffer((void *) args[1], (unsigned) args[2]);
			f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
			break;
		}
		case SYS_WRITE:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 3);
			check_valid_buffer((void *) args[1], (unsigned) args[2]);
			int test = get_kernel_ptr((void *) args[1]);
			f->eax = write(args[0], (const void *) test ,(unsigned) args[2]);
			break;
		}
		case SYS_SEEK:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 2);
			seek(args[0], (unsigned) args[1]);
			break;
		}
		case SYS_TELL:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			f->eax = tell(args[0]);
			break;
		}
		case SYS_CLOSE:
		{
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			close(args[0]);
			break;
		}
		default:
			exit(-1);
	}
}

static void halt (void)
{
	shutdown_power_off();
}

/* Terminates current program , returning status to kernel */
void exit (int status)
{
	struct thread *t = thread_current();
	struct thread *parent = get_thread(t->parent);
	if (parent && t->cp) {
		t->cp->status = status;
	}
	printf ("%s: exit(%d)\n", t->name, status); 
	thread_exit();
	NOT_REACHED();
}

/* Runs executable by name */
static tid_t exec (const char *cmd_line)
{
	tid_t tid = process_execute(cmd_line);
	if (tid != TID_ERROR ) {
        /*printf("Created %s with pid: %d \n\n", cmd_line, tid);*/
		return tid;
	}
	return -1;
}

static int wait (tid_t pid )
{
	int status = process_wait(pid);
	return status;
}

static bool create (const char *file, unsigned initial_size)
{
	lock_acquire(&sysLock);
	bool status = filesys_create(file, initial_size);
	lock_release(&sysLock);
	return status;
}

static bool remove (const char *file)
{
	//synchronize call to file remove from filesys
	lock_acquire(&sysLock);
	bool status = filesys_remove(file);
	lock_release(&sysLock);
	return status;
}

static int open (const char *file)
{
	//synchronize file open from file sys
	lock_acquire(&sysLock);
	struct file *f = filesys_open(file);
	
	// check if the return is valid based on the passed in fd
	if(!f)
	{
		lock_release(&sysLock);
		return -1;
	}
	
	// create and allocate FD and pass in file and fd, then return fd
	struct thread *t = thread_current();
	int fileNum = t->fd;
	t->fd += 1;
	struct FD *newFile = malloc(sizeof (struct FD)); 
	newFile->fd = fileNum;
	newFile->file = f;
	list_push_back (&t->open_files, &newFile->fd_elem);
	lock_release(&sysLock);
	return fileNum;
}

static int filesize (int fd)
{
	// synchronize call to file length
	lock_acquire(&sysLock);
	struct list_elem *e = get_file(fd);
	if(!e)
	{
		lock_release(&sysLock);
		return -1;
	}
	struct FD *fds = list_entry(e, struct FD, fd_elem);
	struct file *file = fds->file;
	off_t size = file_length(file);
	lock_release(&sysLock);
	return size;
}

static int read (int fd, void *buffer, unsigned size)
{
	//synchronize call to read
	lock_acquire(&sysLock);
	struct list_elem *e = get_file(fd);
	if(!e)
	{
		lock_release(&sysLock);
		exit(-1);
	}
	struct FD *fds = list_entry(e, struct FD, fd_elem);
	struct file *file = fds->file;
	int value = file_read (file, buffer, size);
	lock_release(&sysLock);
        return value;                                                        
}

static int write (int fd, const void *buffer, unsigned size)
{
	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		return size;
	}
	else if (fd == STDIN_FILENO) {
		return -1;
	}
	else {
		lock_acquire(&sysLock);
		struct list_elem *e = get_file(fd);
		if (!e) {
			lock_release(&sysLock);
			return -1;
		}
		struct file *file = list_entry(e, struct FD, fd_elem)->file;
		int size_written = file_write(file, buffer, size);
		lock_release(&sysLock);
		return size_written;
	}
}

/* changes next byte to be read or written */
static void seek (int fd, unsigned position)
{
	// synchronize call to seek
	lock_acquire(&sysLock);
	struct list_elem *e = get_file(fd);
	if(!e)
	{
		lock_release(&sysLock);
		exit(-1);
	}
	struct FD *fds = list_entry(e, struct FD, fd_elem);
	struct file *file = fds->file;
	file_seek(file, position);
	lock_release(&sysLock);
}

/* Returns position of next byte to be read or written  */
static unsigned tell (int fd)
{
	//synch call to file tell
	lock_acquire(&sysLock);
	struct list_elem *e = get_file(fd);
	if(!e)
	{
		lock_release(&sysLock);
		return -1;
	}
	struct FD *fds = list_entry(e, struct FD, fd_elem);
	struct file *file = fds->file;
	off_t value = file_tell(file);
	lock_release(&sysLock);
	return value;
}

static void close (int fd)
{
	// synchronize call to close, list_remove, free
	lock_acquire(&sysLock);
	struct list_elem *e = get_file(fd);
	if(!e)
	{
		lock_release(&sysLock);
		return;
	}
	struct FD *fdstruct = list_entry(e, struct FD, fd_elem);
	struct file *file = fdstruct->file;
	file_close(file);
	list_remove(e);
	free(fdstruct);
	lock_release(&sysLock);
}

struct list_elem* get_file(int fd)
{
	struct thread *t = thread_current();
	struct list_elem *e = list_begin(&t->open_files);
	for( ; e != list_end(&t->open_files) ; e = list_next(e))
	{	
		struct FD *fileD = list_entry(e, struct FD, fd_elem);
		if(fd == fileD->fd)
			return e;
	}
	return NULL;
}

/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;
  if (usrc == NULL || dst == NULL) {
    exit(-1);
  }
 
  for (; size > 0; size--, dst++, usrc++) 
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) 
      exit(-1); //thread_exit ();
}

/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
 
  if (us == NULL) {
    exit(-1);
  }
  ks = palloc_get_page (0);
  if (ks == NULL) 
    exit(-1);//thread_exit ();
 
  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user ((uint8_t *) ks + length,(uint8_t *) us++)) 
        {
          palloc_free_page (ks);
          exit(-1); //thread_exit (); 
        }
       
      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}

/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr) 
{
  return (uaddr < PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}

/* Checks buffer + offset to verify that its in vmem and with stack */
static void
check_valid_buffer(const void * one, int size)
{
	//check buffer 2.0
	int i = 0;
	char * temp = (char *) one;
	for(; i < size + 1; i++)
	{
		if(!is_user_vaddr((void *) temp) || (void *) temp < ((void *) 0x8048000))
			exit(-1);
		temp++;
	}
}

static int 
get_kernel_ptr(void *uaddr)
{
	if(!is_user_vaddr(uaddr) || uaddr < ((void*) 0x8048000))
		exit(-1);
	void * ptr = pagedir_get_page(thread_current()->pagedir, uaddr);
	if(!ptr)
		exit(-1);
	return (int) ptr;
}
