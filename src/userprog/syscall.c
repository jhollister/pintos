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


void
syscall_init (void) 
{
	lock_init(&sysLock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
    //printf("\n\nIn syshandler\n\n");
	unsigned callNum;
	int args[3];

    if (!verify_user(f->esp) || f->esp < 0x08048000) {
      exit(-1);
    }
	//## GET SYSCALL NUMBER
	copy_in(&callNum, f->esp, sizeof callNum);

	/*printf("\n\nCalled copyin with callnumber: %d\n\n", callNum);*/


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
			//static bool create (const char *file, unsigned initial_size)
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args *2);
			check_valid_buffer((void *) args[0], (unsigned) args[1]);
			f->eax = create((const char *) args[0], (unsigned) args[1]);
			break;
		}
		case SYS_REMOVE:
		{
			//static bool remove (const char *file)
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			check_valid_buffer((void *) args[0], 0);
			f->eax = remove((const char *) args[0]);
			break;
		}
		case SYS_OPEN:
		{
			//static int open (const char *file)
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			check_valid_buffer((void *) args[0], 0);
			f->eax = open((const char *) args[0]);
			break;
		}
		case SYS_FILESIZE:
		{
			//int filesize (int fd)
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			f->eax = filesize(args[0]);
			break;
		}
		case SYS_READ:
		{
			//int read (int fd, void *buffer, unsigned size)
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 3);
			check_valid_buffer((void *) args[1], (unsigned) args[2]);
			f->eax = read(args[0], (void *) args[1], (unsigned) args[2]);
			break;
		}
		case SYS_WRITE:
		{
			//int write (int fd, const void *buffer, unsigned size)
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 3);
			check_valid_buffer((void *) args[1], (unsigned) args[2]);
			f->eax = write(args[0], (const void *) args[1],(unsigned) args[2]);
			break;
		}
		case SYS_SEEK:
		{
			//void seek (int fd, unsigned position)
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 2);
			seek(args[0], (unsigned) args[1]);
			break;
		}
		case SYS_TELL:
		{
			//unsigned tell (int fd)
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			f->eax = tell(args[0]);
			break;
		}
		case SYS_CLOSE:
		{
			//void close (int fd)
			copy_in(args, (uint32_t *) f->esp + 1, sizeof *args * 1);
			close(args[0]);
			break;
		}
		default:
			/*printf("\n\n Passed in a value greater than syscall is set up for. \n\n");*/
			exit(-1);
	}
}

//*************************************************************************************************************************************


static void halt (void)
{
	shutdown_power_off();
}

void exit (int status)
{
  //struct thread *t = thread_current();
  //if parent is exists and in list of children waited on
  //update parent children list with status
  struct thread *t = thread_current();
  struct thread *parent = get_thread(t->parent);
  if (parent && t->cp) {
    /*printf("Parent is alive\n\n");*/
    t->cp->status = status;
  }
  printf ("%s: exit(%d)\n", t->name, status); 
  thread_exit();
  NOT_REACHED();
/*
Terminates the current user program, returning status to the kernel. If the process's parent waits for it (see below), this is the status that will be returned. Conventionally, a status of 0 indicates success and nonzero values indicate errors.
*/
}

/*
Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this.
*/
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
/*
Waits for a child process pid and retrieves the child's exit status.
If pid is still alive, waits until it terminates. Then, returns the status that pid passed to exit. If pid did not call exit(), but was terminated by the kernel (e.g. killed due to an exception), wait(pid) must return -1. It is perfectly legal for a parent process to wait for child processes that have already terminated by the time the parent calls wait, but the kernel must still allow the parent to retrieve its child's exit status, or learn that the child was terminated by the kernel.

wait must fail and return -1 immediately if any of the following conditions is true:

pid does not refer to a direct child of the calling process. pid is a direct child of the calling process if and only if the calling process received pid as a return value from a successful call to exec.
Note that children are not inherited: if A spawns child B and B spawns child process C, then A cannot wait for C, even if B is dead. A call to wait(C) by process A must fail. Similarly, orphaned processes are not assigned to a new parent if their parent process exits before they do.

The process that calls wait has already called wait on pid. That is, a process may wait for any given child at most once.
Processes may spawn any number of children, wait for them in any order, and may even exit without having waited for some or all of their children. Your design should consider all the ways in which waits can occur. All of a process's resources, including its struct thread, must be freed whether its parent ever waits for it or not, and regardless of whether the child exits before or after its parent.

You must ensure that Pintos does not terminate until the initial process exits. The supplied Pintos code tries to do this by calling process_wait() (in userprog/process.c) from main() (in threads/init.c). We suggest that you implement process_wait() according to the comment at the top of the function and then implement the wait system call in terms of process_wait().

Implementing this system call requires considerably more work than any of the rest.
*/
  /*printf("wait called on pid: %d \n\n", pid);*/
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
	//synchronize call to seek
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
/*
	Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually read (0 at end of file), or -1 if the file could not be read (due to a condition other than end of file). Fd 0 reads from the keyboard using input_getc().
*/
  return 0;
}

static int write (int fd, const void *buffer, unsigned size)
{
/*
Writes size bytes from buffer to the open file fd. Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented by the basic file system. The expected behavior is to write as many bytes as possible up to end-of-file and return the actual number written, or 0 if no bytes could be written at all.

Fd 1 writes to the console. Your code to write to the console should write all of buffer in one call to putbuf(), at least as long as size is not bigger than a few hundred bytes. (It is reasonable to break up larger buffers.) Otherwise, lines of text output by different processes may end up interleaved on the console, confusing both human readers and our grading scripts.
*/
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
    /*printf("Writing file with size: %d\n\n", size);*/
    int size = file_write(file, buffer, size);
    lock_release(&sysLock);
    return size;
  }
}

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
/*
Changes the next byte to be read or written in open file fd to position, expressed in bytes from the beginning of the file. (Thus, a position of 0 is the file's start.)
A seek past the current end of a file is not an error. A later read obtains 0 bytes, indicating end of file. A later write extends the file, filling any unwritten gap with zeros. (However, in Pintos files have a fixed length until project 4 is complete, so writes past end of file will return an error.) These semantics are implemented in the file system and do not require any special effort in system call implementation.
*/
}

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
/*
Returns the position of the next byte to be read or written in open file fd, expressed in bytes from the beginning of the file.
*/
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

/**************************************** HANDLER HELPER FUNCTIONS ******************************************/

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

static void
check_valid_buffer(const void * one, int size)
{
	
	//check buffer
//	int i = 0;
//	for(; i < size + 1; i++)
//	{
//		if(!verify_user(one + i))
//			exit(-1);
//	}
	
	//check end points
	if(!verify_user(one) || !verify_user(one + size))
	{
//		printf("\n\n We are exiting from check valid pointer \n\n");
		exit(-1);
	}
}

