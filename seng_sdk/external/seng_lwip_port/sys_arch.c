#include "arch/cc.h"

#include <errno.h>
#include <assert.h>

#include "lwip/debug.h" // for ASSERT, but opt.h also includes it anyway

#include "lwip/opt.h"
#include "lwip/tcpip.h"

#include <sgx_spinlock.h>
#include <sgx_thread.h> //#include <pthread.h>

#include <sgx_trts.h> // sgx_read_rand

#include "seng_threads_t.h"

//#define PORT_DEBUG

// libc:  int rand(void); -- return a value between 0 and RAND_MAX (inclusive)
// sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes);
unsigned int seng_rand(void) {
  unsigned char r[4];
  sgx_status_t status = sgx_read_rand(r, sizeof(r));
  // I think this should only fail when a VMM blocks RDRAND instruction
  if (status != SGX_SUCCESS) abort();
  return r[0] << 24 | r[1] << 16 | r[2] << 8 | r[3];
}

// get rid of undefined fflush() if LWIP_ASSERT is not disabled via LWIP_NOASSERT
/*
int fflush(void* stream)
{
  if (stream == 0) return 0;
  else return 0;
}
*/


// TODO: cf. papers for creating monotonic timers inside enclave, e.g. via counter thread
// TODO: or check out sgx_get_trusted_time for CSE/ME provided counter
//        ~ https://github.com/intel/linux-sgx/issues/161
static void
get_untrusted_monotonic_time(struct timespec *ts)
{
 // clock_gettime(CLOCK_MONOTONIC, ts);
    sgx_status_t status;
    int res;
    status = seng_clock_gettime(&res, CLOCK_MONOTONIC, (struct seng_timespec *)ts);
    if (status != SGX_SUCCESS) abort();
}

/* Might slightly reduce OCALLs on high poll-recv load */
//#define LIGHT_SPINLOCK 1

#if SYS_LIGHTWEIGHT_PROT

#ifdef LIGHT_SPINLOCK
static sgx_spinlock_t lwprot_slock = SGX_SPINLOCK_INITIALIZER;  
#else
static sgx_thread_mutex_t lwprot_mutex = SGX_THREAD_MUTEX_INITIALIZER;
#endif
static sgx_thread_t lwprot_thread = (sgx_thread_t)0xDEAD;
static int lwprot_count = 0;
#endif /* SYS_LIGHTWEIGHT_PROT */

static struct sys_thread *threads = NULL;
static sgx_thread_mutex_t threads_mutex = SGX_THREAD_MUTEX_INITIALIZER;

struct sys_mbox_msg {
  struct sys_mbox_msg *next;
  void *msg;
};

#define SYS_MBOX_SIZE 128

struct sys_mbox {
  int first, last;
  void *msgs[SYS_MBOX_SIZE];
  struct sys_sem *not_empty;
  struct sys_sem *not_full;
  //struct sys_sem *mutex;
  sgx_spinlock_t s_lock;
  int wait_send;
};

struct sys_sem {
  unsigned int c;
  sgx_thread_condattr_t condattr;
  sgx_thread_cond_t cond;
  sgx_thread_mutex_t mutex;
};

/* Important if using CORE_LOCKING:=1, bcs. core lock contention will otherwise
 * cause a lot of OCALLs for mutex sleep/wakeup */
#define CORE_SPIN_LOCK

struct sys_mutex {
#ifndef CORE_SPIN_LOCK
  sgx_thread_mutex_t mutex;
#else
  sgx_spinlock_t mutex;
#endif
};

struct sys_thread {
  struct sys_thread *next;
  sgx_thread_t pthread;
};

static struct sys_sem *sys_sem_new_internal(u8_t count);
static void sys_sem_free_internal(struct sys_sem *sem);

static u32_t cond_wait(sgx_thread_cond_t * cond, sgx_thread_mutex_t * mutex,
                       u32_t timeout);

/*-----------------------------------------------------------------------------------*/
/* Threads */



static struct sys_thread * 
introduce_thread(sgx_thread_t id)
{
  struct sys_thread *thread;

  thread = (struct sys_thread *)malloc(sizeof(struct sys_thread));

  if (thread != NULL) {
    sgx_thread_mutex_lock(&threads_mutex);
    thread->next = threads;
    thread->pthread = id;
    threads = thread;
    sgx_thread_mutex_unlock(&threads_mutex);
  }

  return thread;
}

struct thread_wrapper_data *thread_data_list = NULL;
static sgx_thread_mutex_t thread_data_list_mutex = SGX_THREAD_MUTEX_INITIALIZER;

struct thread_wrapper_data
{
  struct thread_wrapper_data *next;
  struct sys_sem *has_started;
  sgx_thread_t thread_id;
  lwip_thread_fn function;
  void *arg;
};

int
start_new_seng_thread(void)
{
  struct thread_wrapper_data *thread_data = NULL;

  sgx_thread_mutex_lock(&thread_data_list_mutex);
  if (thread_data_list != NULL) {
    thread_data = thread_data_list;
    thread_data_list = thread_data->next;
  }
  sgx_thread_mutex_unlock(&thread_data_list_mutex);

  if (thread_data == NULL) return -1; // fail

  // register thread id and wake up parent/initiator process
  thread_data->thread_id = sgx_thread_self();
  sys_sem_signal(&thread_data->has_started);

#ifdef PORT_DEBUG
  printf("Going to run new thread now\n");
#endif

  // start the function with requested arguemnts
  thread_data->function(thread_data->arg);
  return 0;
}

sys_thread_t
sys_thread_new(const char *name, lwip_thread_fn function, void *arg, int stacksize, int prio)
{
#ifdef PORT_DEBUG
  printf("sys_thread_new got called\n");
#endif

  struct sys_thread *st = NULL;
  struct thread_wrapper_data *thread_data;
//  LWIP_UNUSED_ARG(name);
  LWIP_UNUSED_ARG(stacksize);
  LWIP_UNUSED_ARG(prio);

  thread_data = (struct thread_wrapper_data *)malloc(sizeof(struct thread_wrapper_data));
  thread_data->arg = arg;
  thread_data->function = function;
  thread_data->thread_id = SGX_THREAD_T_NULL;
  thread_data->next = NULL;
  if (ERR_MEM == sys_sem_new(&thread_data->has_started, 0)) abort();

  // put at end of thread_wrapper_data list
  sgx_thread_mutex_lock(&thread_data_list_mutex);
  struct thread_wrapper_data **t = &thread_data_list;
  for (; *t != NULL; t = &((*t)->next));
  *t = thread_data;
  sgx_thread_mutex_unlock(&thread_data_list_mutex);

  // start thread
  int res = -1;
  sgx_status_t status = create_new_seng_thread(&res, name);
  if (status != SGX_SUCCESS || res != 0) abort();

  // wait for thread to start (experimental 2sec timeout,
  // bcs. no fail feedback, yet -- i.e. if not enough TCS)
  if (SYS_ARCH_TIMEOUT == sys_arch_sem_wait(&thread_data->has_started, 2000)
    || SGX_THREAD_T_NULL == thread_data->thread_id) {
    abort();
  }

#ifdef PORT_DEBUG
  printf("Successfully got woken up by spawned thread\n");
#endif

  st = introduce_thread(thread_data->thread_id);
  if (NULL == st) {
    abort();
  }

  // clean up now as thread is running has reported back
  sys_sem_free(&thread_data->has_started);
  free(thread_data);
  return st;
}

#if LWIP_TCPIP_CORE_LOCKING
static sgx_thread_t lwip_core_lock_holder_thread_id;
void sys_lock_tcpip_core(void)
{
  sys_mutex_lock(&lock_tcpip_core);
  lwip_core_lock_holder_thread_id = sgx_thread_self();
}

void sys_unlock_tcpip_core(void)
{
  lwip_core_lock_holder_thread_id = 0;
  sys_mutex_unlock(&lock_tcpip_core);
}
#endif /* LWIP_TCPIP_CORE_LOCKING */

static sgx_thread_t lwip_tcpip_thread_id;
void sys_mark_tcpip_thread(void)
{
  lwip_tcpip_thread_id = sgx_thread_self();
}

void sys_check_core_locking(void)
{
  if (lwip_tcpip_thread_id != 0) {
    sgx_thread_t current_thread_id = sgx_thread_self();

// added assert() bcs. coonfigured LWIP_NOASSERT to get rid of "fflush()" requirement
// but remember that assert() removes statements in non-debug
#if LWIP_TCPIP_CORE_LOCKING
    //LWIP_ASSERT("Function called without core lock", current_thread_id == lwip_core_lock_holder_thread_id);
    assert (current_thread_id == lwip_core_lock_holder_thread_id);
#else /* LWIP_TCPIP_CORE_LOCKING */
    //LWIP_ASSERT("Function called from wrong thread", current_thread_id == lwip_tcpip_thread_id);
    assert (current_thread_id == lwip_tcpip_thread_id);
#endif /* LWIP_TCPIP_CORE_LOCKING */
  }
}

/*-----------------------------------------------------------------------------------*/
/* Mailbox */
err_t
sys_mbox_new(struct sys_mbox **mb, int size)
{
  struct sys_mbox *mbox;
  LWIP_UNUSED_ARG(size);

  mbox = (struct sys_mbox *)malloc(sizeof(struct sys_mbox));
  if (mbox == NULL) {
    return ERR_MEM;
  }
  mbox->first = mbox->last = 0;
  mbox->not_empty = sys_sem_new_internal(0);
  mbox->not_full = sys_sem_new_internal(0);
  //mbox->mutex = sys_sem_new_internal(1);
  mbox->s_lock = SGX_SPINLOCK_INITIALIZER; // 0, bcs. otherwise direct deadlock!
  mbox->wait_send = 0;

  *mb = mbox;
  return ERR_OK;
}

void
sys_mbox_free(struct sys_mbox **mb)
{
  if ((mb != NULL) && (*mb != SYS_MBOX_NULL)) {
    struct sys_mbox *mbox = *mb;
    //sys_arch_sem_wait(&mbox->mutex, 0);
    sgx_spin_lock(&mbox->s_lock);
    
    sys_sem_free_internal(mbox->not_empty);
    sys_sem_free_internal(mbox->not_full);
    //sys_sem_free_internal(mbox->mutex);
    mbox->not_empty = mbox->not_full = NULL; // mbox->mutex = NULL;
    mbox->s_lock = SGX_SPINLOCK_INITIALIZER;
    free(mbox);
  }
}

err_t
sys_mbox_trypost(struct sys_mbox **mb, void *msg)
{
  u8_t first;
  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  //sys_arch_sem_wait(&mbox->mutex, 0);
  sgx_spin_lock(&mbox->s_lock);

  if ((mbox->last + 1) >= (mbox->first + SYS_MBOX_SIZE)) {
    //sys_sem_signal(&mbox->mutex);
    sgx_spin_unlock(&mbox->s_lock);
    return ERR_MEM;
  }

  mbox->msgs[mbox->last % SYS_MBOX_SIZE] = msg;

  if (mbox->last == mbox->first) {
    first = 1;
  } else {
    first = 0;
  }

  mbox->last++;

  if (first) {
    sys_sem_signal(&mbox->not_empty);
  }

  //sys_sem_signal(&mbox->mutex);
  sgx_spin_unlock(&mbox->s_lock);

  return ERR_OK;
}

err_t
sys_mbox_trypost_fromisr(sys_mbox_t *q, void *msg)
{
  return sys_mbox_trypost(q, msg);
}

void
sys_mbox_post(struct sys_mbox **mb, void *msg)
{
  u8_t first;
  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  //sys_arch_sem_wait(&mbox->mutex, 0);
  sgx_spin_lock(&mbox->s_lock);

  while ((mbox->last + 1) >= (mbox->first + SYS_MBOX_SIZE)) {
    mbox->wait_send++;
    //sys_sem_signal(&mbox->mutex);
    sgx_spin_unlock(&mbox->s_lock);
    sys_arch_sem_wait(&mbox->not_full, 0);
    //sys_arch_sem_wait(&mbox->mutex, 0);
    sgx_spin_lock(&mbox->s_lock);
    mbox->wait_send--;
  }

  mbox->msgs[mbox->last % SYS_MBOX_SIZE] = msg;

  if (mbox->last == mbox->first) {
    first = 1;
  } else {
    first = 0;
  }

  mbox->last++;

  if (first) {
    sys_sem_signal(&mbox->not_empty);
  }

  //sys_sem_signal(&mbox->mutex);
  sgx_spin_unlock(&mbox->s_lock);
}

u32_t
sys_arch_mbox_tryfetch(struct sys_mbox **mb, void **msg)
{
  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  //sys_arch_sem_wait(&mbox->mutex, 0);
  sgx_spin_lock(&mbox->s_lock);

  if (mbox->first == mbox->last) {
    //sys_sem_signal(&mbox->mutex);
    sgx_spin_unlock(&mbox->s_lock);
    return SYS_MBOX_EMPTY;
  }

  if (msg != NULL) {
    *msg = mbox->msgs[mbox->first % SYS_MBOX_SIZE];
  }

  mbox->first++;

  if (mbox->wait_send) {
    sys_sem_signal(&mbox->not_full);
  }

  //sys_sem_signal(&mbox->mutex);
  sgx_spin_unlock(&mbox->s_lock);

  return 0;
}

// NOTE: return value "time_needed" seems to be used by lwIP only for TIMEOUT detection
u32_t
sys_arch_mbox_fetch(struct sys_mbox **mb, void **msg, u32_t timeout)
{
  u32_t time_needed = 0;
  struct sys_mbox *mbox;
  LWIP_ASSERT("invalid mbox", (mb != NULL) && (*mb != NULL));
  mbox = *mb;

  /* The mutex lock is quick so we don't bother with the timeout
     stuff here. */
  //sys_arch_sem_wait(&mbox->mutex, 0);
  sgx_spin_lock(&mbox->s_lock);

  while (mbox->first == mbox->last) {
    //sys_sem_signal(&mbox->mutex);
    sgx_spin_unlock(&mbox->s_lock);

    /* We block while waiting for a mail to arrive in the mailbox. We
       must be prepared to timeout. */
    if (timeout != 0) {
      time_needed = sys_arch_sem_wait(&mbox->not_empty, timeout);

      if (time_needed == SYS_ARCH_TIMEOUT) {
        return SYS_ARCH_TIMEOUT;
      }
    } else {
      sys_arch_sem_wait(&mbox->not_empty, 0);
    }

    //sys_arch_sem_wait(&mbox->mutex, 0);
    sgx_spin_lock(&mbox->s_lock);
  }

  if (msg != NULL) {
    *msg = mbox->msgs[mbox->first % SYS_MBOX_SIZE];
  }

  mbox->first++;

  if (mbox->wait_send) {
    sys_sem_signal(&mbox->not_full);
  }

  //sys_sem_signal(&mbox->mutex);
  sgx_spin_unlock(&mbox->s_lock);

  return time_needed;
}

/*-----------------------------------------------------------------------------------*/
/* Semaphore */
static struct sys_sem *
sys_sem_new_internal(u8_t count)
{
  struct sys_sem *sem;

  sem = (struct sys_sem *)malloc(sizeof(struct sys_sem));
  if (sem != NULL) {
    sem->c = count;
    // condattr only dummy (unused) in SGX SDK
    //sgx_thread_condattr_init(&(sem->condattr));

    // not available in SDK, bcs. condattr is dummy; but note psw uses futex() for waits and
    // that if they would use timeouts, futex() would by default use CLOCK_MONOTONIC
    //sgx_thread_condattr_setclock(&(sem->condattr), CLOCK_MONOTONIC);

    sgx_thread_cond_init(&(sem->cond), &(sem->condattr));
    sgx_thread_mutex_init(&(sem->mutex), NULL);
  }
  return sem;
}

err_t
sys_sem_new(struct sys_sem **sem, u8_t count)
{
  *sem = sys_sem_new_internal(count);
  if (*sem == NULL) {
    return ERR_MEM;
  }
  return ERR_OK;
}

// timeout in milli seconds
static u32_t
cond_wait(sgx_thread_cond_t *cond, sgx_thread_mutex_t *mutex, u32_t timeout)
{
  seng_timespec_t ts;
  int ret;

//#ifdef __GNU__
//  #define sgx_thread_cond_wait sgx_thread_hurd_cond_wait_np
//  #define sgx_thread_cond_timedwait sgx_thread_hurd_cond_timedwait_np
//#endif

  if (timeout == 0) {
    sgx_thread_cond_wait(cond, mutex);
    return 0;
  }

  /* Get a timestamp and add the timeout value.
  get_untrusted_monotonic_time(&rtime1);
  ts.tv_sec = rtime1.tv_sec + timeout / 1000L;
  ts.tv_nsec = rtime1.tv_nsec + (timeout % 1000L) * 1000000L;
  if (ts.tv_nsec >= 1000000000L) {
    ts.tv_sec++;
    ts.tv_nsec -= 1000000000L;
  } */

  /* Use relative timeout */
  // NOTE: current version does NOT return "time_needed" value, only 0 or timeout
  ts.tv_sec = timeout / 1000L;
  ts.tv_nsec = (timeout % 1000L) * 1000000L;
  if (ts.tv_nsec >= 1000000000L) {
    ts.tv_sec++;
    ts.tv_nsec -= 1000000000L;
  }

  ret = sgx_thread_cond_timedwait(cond, mutex, &ts);
  if (ret == ETIMEDOUT) {
    return SYS_ARCH_TIMEOUT;
  }

  /* Calculate for how long we waited for the cond.
  get_untrusted_monotonic_time(&rtime2);
  ts.tv_sec = rtime2.tv_sec - rtime1.tv_sec;
  ts.tv_nsec = rtime2.tv_nsec - rtime1.tv_nsec;
  if (ts.tv_nsec < 0) {
    ts.tv_sec--;
    ts.tv_nsec += 1000000000L;
  }
  return (u32_t)(ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);*/
  return 0;
}

u32_t
sys_arch_sem_wait(struct sys_sem **s, u32_t timeout)
{
  u32_t time_needed = 0;
  struct sys_sem *sem;
  LWIP_ASSERT("invalid sem", (s != NULL) && (*s != NULL));
  sem = *s;

  sgx_thread_mutex_lock(&(sem->mutex));
  while (sem->c <= 0) {
    if (timeout > 0) {
      time_needed = cond_wait(&(sem->cond), &(sem->mutex), timeout);

      if (time_needed == SYS_ARCH_TIMEOUT) {
        sgx_thread_mutex_unlock(&(sem->mutex));
        return SYS_ARCH_TIMEOUT;
      }
      /*      pthread_mutex_unlock(&(sem->mutex));
              return time_needed; */
    } else {
      cond_wait(&(sem->cond), &(sem->mutex), 0);
    }
  }
  sem->c--;
  sgx_thread_mutex_unlock(&(sem->mutex));
  return (u32_t)time_needed;
}

void
sys_sem_signal(struct sys_sem **s)
{
  struct sys_sem *sem;
  LWIP_ASSERT("invalid sem", (s != NULL) && (*s != NULL));
  sem = *s;

  sgx_thread_mutex_lock(&(sem->mutex));
  sem->c++;

  if (sem->c > 1) {
    sem->c = 1;
  }

  sgx_thread_cond_broadcast(&(sem->cond));
  sgx_thread_mutex_unlock(&(sem->mutex));
}

static void
sys_sem_free_internal(struct sys_sem *sem)
{
  sgx_thread_cond_destroy(&(sem->cond));
  // condattr dummy/unused in SGX SDK, so no destroy method
  //sgx_thread_condattr_destroy(&(sem->condattr));
  sgx_thread_mutex_destroy(&(sem->mutex));
  free(sem);
}

void
sys_sem_free(struct sys_sem **sem)
{
  if ((sem != NULL) && (*sem != SYS_SEM_NULL)) {
    sys_sem_free_internal(*sem);
  }
}

/*-----------------------------------------------------------------------------------*/
/* Mutex */
/** Create a new mutex
 * @param mutex pointer to the mutex to create
 * @return a new mutex */
err_t
sys_mutex_new(struct sys_mutex **mutex)
{
  struct sys_mutex *mtx;

  mtx = (struct sys_mutex *)malloc(sizeof(struct sys_mutex));
  if (mtx != NULL) {
#ifndef CORE_SPIN_LOCK
    sgx_thread_mutex_init(&(mtx->mutex), NULL);
#else
    mtx->mutex = SGX_SPINLOCK_INITIALIZER;
#endif
    *mutex = mtx;
    return ERR_OK;
  }
  else {
    return ERR_MEM;
  }
}

/** Lock a mutex
 * @param mutex the mutex to lock */
void
sys_mutex_lock(struct sys_mutex **mutex)
{
#ifndef CORE_SPIN_LOCK
  sgx_thread_mutex_lock(&((*mutex)->mutex));
#else
  sgx_spin_lock(&(*mutex)->mutex);
#endif
}

/** Unlock a mutex
 * @param mutex the mutex to unlock */
void
sys_mutex_unlock(struct sys_mutex **mutex)
{
#ifndef CORE_SPIN_LOCK
  sgx_thread_mutex_unlock(&((*mutex)->mutex));
#else
  sgx_spin_unlock(&(*mutex)->mutex);
#endif
}

/** Delete a mutex
 * @param mutex the mutex to delete */
void
sys_mutex_free(struct sys_mutex **mutex)
{
#ifndef CORE_SPIN_LOCK
  sgx_thread_mutex_destroy(&((*mutex)->mutex));
#else
  (*mutex)->mutex = SGX_SPINLOCK_INITIALIZER;
#endif
  free(*mutex);
}

/*-----------------------------------------------------------------------------------*/
/* Time */
u32_t
sys_now(void)
{
  struct timespec ts;

  get_untrusted_monotonic_time(&ts);
  return (u32_t)(ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);
}

u32_t
sys_jiffies(void)
{
  struct timespec ts;

  get_untrusted_monotonic_time(&ts);
  return (u32_t)(ts.tv_sec * 1000000000L + ts.tv_nsec);
}

/*-----------------------------------------------------------------------------------*/
/* Init */

void
sys_init(void)
{
}

/*-----------------------------------------------------------------------------------*/
/* Critical section */
#if SYS_LIGHTWEIGHT_PROT
/** sys_prot_t sys_arch_protect(void)

This optional function does a "fast" critical region protection and returns
the previous protection level. This function is only called during very short
critical regions. An embedded system which supports ISR-based drivers might
want to implement this function by disabling interrupts. Task-based systems
might want to implement this by using a mutex or disabling tasking. This
function should support recursive calls from the same task or interrupt. In
other words, sys_arch_protect() could be called while already protected. In
that case the return value indicates that it is already protected.

sys_arch_protect() is only required if your port is supporting an operating
system.
*/
sys_prot_t
sys_arch_protect(void)
{
    /* Note that for the UNIX port, we are using a lightweight mutex, and our
     * own counter (which is locked by the mutex). The return code is not actually
     * used. */
    if (lwprot_thread != sgx_thread_self())
    {
        /* We are locking the mutex where it has not been locked before *
        * or is being locked by another thread */
#ifdef LIGHT_SPINLOCK
        sgx_spin_lock(&lwprot_slock);
#else
        sgx_thread_mutex_lock(&lwprot_mutex);
#endif
        lwprot_thread = sgx_thread_self();
        lwprot_count = 1;
    }
    else
        /* It is already locked by THIS thread */
        lwprot_count++;
    return 0;
}

/** void sys_arch_unprotect(sys_prot_t pval)

This optional function does a "fast" set of critical region protection to the
value specified by pval. See the documentation for sys_arch_protect() for
more information. This function is only required if your port is supporting
an operating system.
*/
void
sys_arch_unprotect(sys_prot_t pval)
{
    LWIP_UNUSED_ARG(pval);
    if (lwprot_thread == sgx_thread_self())
    {
        lwprot_count--;
        if (lwprot_count == 0)
        {
            lwprot_thread = (sgx_thread_t) 0xDEAD;
#ifdef LIGHT_SPINLOCK
            sgx_spin_unlock(&lwprot_slock);
#else
            sgx_thread_mutex_unlock(&lwprot_mutex);
#endif
        }
    }
}
#endif /* SYS_LIGHTWEIGHT_PROT */
