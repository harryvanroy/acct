#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/fcntl.h>
#include <sys/syslog.h>
#include <sys/kernel.h>
#include <sys/namei.h>
#include <sys/errno.h>
#include <sys/resource.h>
#include <sys/resourcevar.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/filio.h>
#include <sys/kthread.h>
#include <sys/syscallargs.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/smr.h>
#include <sys/mutex.h>
#include <machine/intr.h>

#include "acct.h"

union message_type {
        struct acct_fork *fork;
        struct acct_exec *exec;
        struct acct_exit *exit;
};

struct message {
        TAILQ_ENTRY(message) entry;
        union message_type msg;
        unsigned short acct_type;
};

TAILQ_HEAD(messages, message);
struct messages message_queue;

// Sequence number counter
unsigned int seq_count;

// Flag for whether or not file is open
int is_open;

// Read/write lock for message queue
struct mutex acct_lock;

void
create_acct_common(struct acct_common *comm, struct process *process)
{
        // Command name - only take first 16 chars
        memcpy(comm->ac_comm, process->ps_comm, 16);

        comm->ac_seq = seq_count;

        // Wrap seq_count if last bit set
        if (seq_count == 0x40000000)
                seq_count = 0x01;
        else 
                seq_count = seq_count << 1;
        
        // Process id, user id and group id
        comm->ac_pid = process->ps_pid;
        comm->ac_uid = process->ps_ucred->cr_ruid;
        comm->ac_gid = process->ps_ucred->cr_rgid;
        
        // Accounting flags
        comm->ac_flag = process->ps_acflag;

        // Elapsed and starting time
        comm->ac_btime = process->ps_start;
        comm->ac_etime = process->ps_tu.tu_runtime;

        // Terminal that process was started
        if ((process->ps_flags & PS_CONTROLT) &&
            process->ps_pgrp->pg_session->s_ttyp)
                comm->ac_tty = process->ps_pgrp->pg_session->s_ttyp->t_dev;
}

/*
 * Called when process forks. 
 */
void
acct_fork(struct process *process_fork)
{
        if (!is_open)
                return;
        struct message *new_message = malloc(sizeof(struct message), M_DEVBUF, 
                                        M_CANFAIL | M_NOWAIT | M_ZERO);

        // Populate acct_comm
        struct acct_common comm;
        comm.ac_type = ACCT_MSG_FORK;
        comm.ac_len = sizeof(struct acct_fork);
        create_acct_common(&comm, process_fork->ps_pptr);

        new_message->msg.fork = malloc(sizeof(struct acct_fork), M_DEVBUF, 
                                        M_CANFAIL | M_NOWAIT | M_ZERO);
        memcpy(&new_message->msg.fork->ac_common, &comm, 
            sizeof(struct acct_common));
        new_message->acct_type = ACCT_MSG_FORK;

        // Child process id
        new_message->msg.fork->ac_cpid = process_fork->ps_pid;
        
        uprintf("fork: pid - %d uid - %d gid - %d comm - %s seq - %d cpid - %d\n", 
                        new_message->msg.fork->ac_common.ac_pid,
                        new_message->msg.fork->ac_common.ac_uid,
                        new_message->msg.fork->ac_common.ac_gid,
                        new_message->msg.fork->ac_common.ac_comm,
                        new_message->msg.fork->ac_common.ac_seq,
                        new_message->msg.fork->ac_cpid);

        // Insert message into queue
        mtx_enter(&acct_lock);
        TAILQ_INSERT_TAIL(&message_queue, new_message, entry);
        mtx_leave(&acct_lock);
        
        // Wake up tsleep-ing process
        wakeup(&message_queue);
}

/*
 * Called when process execs.
 */
void
acct_exec(struct process *process_exec)
{
        if (!is_open)
                return;
        struct message *new_message = malloc(sizeof(struct message), M_DEVBUF, 
                                        M_CANFAIL | M_NOWAIT | M_ZERO);

        // Populate acct_common
        struct acct_common comm;
        comm.ac_type = ACCT_MSG_EXEC;
        comm.ac_len = sizeof(struct acct_exec);
        create_acct_common(&comm, process_exec);

        new_message->msg.exec = malloc(sizeof(struct acct_exec), M_DEVBUF, 
                                        M_CANFAIL | M_NOWAIT | M_ZERO);
        memcpy(&new_message->msg.exec->ac_common, &comm, 
            sizeof(struct acct_common));
        new_message->acct_type = ACCT_MSG_EXEC;
       
        uprintf("exec: pid - %d uid - %d gid - %d comm - %s seq - %d\n", 
                        new_message->msg.fork->ac_common.ac_pid,
                        new_message->msg.fork->ac_common.ac_uid,
                        new_message->msg.fork->ac_common.ac_gid,
                        new_message->msg.fork->ac_common.ac_comm,
                        new_message->msg.fork->ac_common.ac_seq);
       
        // Insert message into queue
        mtx_enter(&acct_lock);
        TAILQ_INSERT_TAIL(&message_queue, new_message, entry);
        mtx_leave(&acct_lock);

        // Wake up tsleep-ing process
        wakeup(&message_queue);
}

/*
 * Called when process exits.
 */
void
acct_exit(struct process *process_exit)
{
        if (!is_open) 
                return;
        struct message *new_message = malloc(sizeof(struct message), M_DEVBUF, 
                                        M_CANFAIL | M_NOWAIT | M_ZERO);
        
        struct acct_common comm;
        comm.ac_type = ACCT_MSG_EXIT;
        comm.ac_len = sizeof(struct acct_exit);
        create_acct_common(&comm, process_exit);

        new_message->msg.exit = malloc(sizeof(struct acct_exit), M_DEVBUF, 
                                        M_CANFAIL | M_NOWAIT | M_ZERO);
        memcpy(&new_message->msg.exit->ac_common, &comm, 
            sizeof(struct acct_common));
        new_message->acct_type = ACCT_MSG_EXIT;

        // User time and system time
        struct timespec user_time, system_time;
        calctsru(&process_exit->ps_tu, &user_time, &system_time, NULL);
        new_message->msg.exit->ac_utime = user_time;
        new_message->msg.exit->ac_stime = system_time;

         // Mem and io 
        struct rusage *p_stats = &process_exit->ps_mainproc->p_ru;
        new_message->msg.exit->ac_io = p_stats->ru_inblock + p_stats->ru_oublock;
        new_message->msg.exit->ac_mem = 
            p_stats->ru_ixrss + p_stats->ru_idrss + p_stats->ru_isrss;


        uprintf("exit: pid - %d uid - %d gid - %d comm - %s seq - %d\n", 
                        new_message->msg.fork->ac_common.ac_pid,
                        new_message->msg.fork->ac_common.ac_uid,
                        new_message->msg.fork->ac_common.ac_gid,
                        new_message->msg.fork->ac_common.ac_comm,
                        new_message->msg.fork->ac_common.ac_seq);
      
        // Insert message into queue
        mtx_enter(&acct_lock);
        TAILQ_INSERT_TAIL(&message_queue, new_message, entry);
        mtx_leave(&acct_lock);

        // Wake up tsleep-ing queue
        wakeup(&message_queue);
}

/*
 * Called when kernel starts running. 
 */
void
acctattach(struct process *proc)
{
        seq_count = 0x01;
        mtx_init(&acct_lock, 0);
        TAILQ_INIT(&message_queue);
}

/*
 * Called when userland program attempts to open device file.
 */
int
acctopen(dev_t dev, int oflags, int devtype, struct proc *p)
{
        if (is_open)
                return (EPERM);
        if (minor(dev) != 0)
                return (ENXIO);
        if (oflags & FWRITE)
                return (EPERM);

        seq_count = 0x01;
        is_open = 1;

        return (0);
}

/*
 * Called when userland program closes device file.
 */
int
acctclose(dev_t dev, int fflag, int devtype, struct proc *p)
{
        struct message *message;

        mtx_enter(&acct_lock);

        // Clear the messages from the queue
        while (!TAILQ_EMPTY(&message_queue)) {
                message = TAILQ_FIRST(&message_queue);
                TAILQ_REMOVE(&message_queue, message, entry);
                if (message->acct_type == ACCT_MSG_FORK) {
                        free(message->msg.fork, M_DEVBUF, 
                            sizeof(struct acct_fork));
                } else if (message->acct_type == ACCT_MSG_EXEC) {
                        free(message->msg.exec, M_DEVBUF, 
                            sizeof(struct acct_exec));
                } else if (message->acct_type == ACCT_MSG_EXIT) {

                        free(message->msg.exit, M_DEVBUF, 
                            sizeof(struct acct_exit));
                }
                free(message, M_DEVBUF, sizeof(struct message));
        }

        mtx_leave(&acct_lock);
        is_open = 0;
        
        return (0);
}

/*
 * Called when userland program attempts to read from device file.
 */
int
acctread(dev_t dev, struct uio *uio, int ioflag)
{
        int err = 0;
        struct message *message_return = malloc(sizeof(struct message), 
                                M_DEVBUF, M_CANFAIL | M_NOWAIT | M_ZERO);
        
        if (uio->uio_offset < 0)
                return (EINVAL);

        if (TAILQ_EMPTY(&message_queue)) {
                err = tsleep(&message_queue, PRIBIO | PCATCH, "empty", 0);
                if (err)
                        return (err);
        }

        message_return = TAILQ_FIRST(&message_queue);
        
        mtx_enter(&acct_lock);
        TAILQ_REMOVE(&message_queue, message_return, entry);
        mtx_leave(&acct_lock);

        size_t len;
        if (message_return->acct_type == ACCT_MSG_FORK) {
                len = message_return->msg.fork->ac_common.ac_len;
                if (uio->uio_resid >= len) {
                        if ((err = uiomove((void*)message_return->msg.fork,
                            sizeof(struct acct_fork), uio)) != 0)
                                return (err);
                        free(message_return->msg.fork, M_DEVBUF, 
                            sizeof(struct acct_fork));
                }
        }
        else if (message_return->acct_type == ACCT_MSG_EXEC) {
                len = message_return->msg.exec->ac_common.ac_len;
                if (uio->uio_resid >= len) {
                        if ((err = uiomove((void*)message_return->msg.exec,
                            sizeof(struct acct_exec), uio)) != 0)
                                return (err);
                        free(message_return->msg.exec, M_DEVBUF,
                            sizeof(struct acct_exec));
                }
        }
        else if (message_return->acct_type == ACCT_MSG_EXIT) {
                len = message_return->msg.exit->ac_common.ac_len;
                if (uio->uio_resid >= len) {
                        if ((err = uiomove((void*)message_return->msg.exit,
                            sizeof(struct acct_exit), uio)) != 0)
                                return (err);
                        free(message_return->msg.exit, M_DEVBUF, 
                            sizeof(struct acct_exit));
                }
        }

        free(message_return, M_DEVBUF, sizeof(struct message));
        return (0);
}

/*
 * Called when ioctl called on device file.
 */
int
acctioctl(dev_t dev, u_long cmd, caddr_t data, int fflag, struct proc *p)
{
        if (cmd == FIONREAD) {
                if (TAILQ_EMPTY(&message_queue))
                        return 0;
                struct message *message = TAILQ_FIRST(&message_queue);
                if (message->acct_type == ACCT_MSG_FORK)
                        *data = message->msg.fork->ac_common.ac_len;
                else if (message->acct_type == ACCT_MSG_EXEC)
                        *data = message->msg.exec->ac_common.ac_len;
                else if (message->acct_type == ACCT_MSG_EXIT)
                        *data = message->msg.exit->ac_common.ac_len;
        }
        return (0);
}

/*
 * Called when userland program attempts to write to device file.
 * Returns EOPNOTSUPP as driver does not support being written to
 * by userland process.
 */
int
acctwrite(dev_t dev, struct uio *uio, int ioflag)
{
        return (EOPNOTSUPP);
}

int
acctkqfilter(dev_t dev, struct knote *kn)
{
        return (0);
}

int
acctpoll(dev_t dev, int events, struct proc *p)
{
        return (0);
}
