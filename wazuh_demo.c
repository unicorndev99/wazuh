
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

#define     BASE_DIR        NULL
#define     PATH_SEP        '/'
#define     OS_SIZE_1024    1024
#define     OS_SIZE_2048    2048
#define     MAX_PID         32768
#define     PROC            0      
#define     PID             1
#define     TASK            2
#define     ROOTKIT_ALERT   "INFO: "
#define     SYSTEM_CRIT     "WARN: "

/* Global variables for hidden files*/
static int _sys_errors;
static int _sys_total;
static dev_t did;
static int _dev_errors;
static int _dev_total;

/* Global variables for hidden processes*/
int noproc;
int proc_pid_found;

/* Log */
void notify_rk(char *header, char *msg)
{

    char current_time[32];
    struct tm* to;
    time_t t;
    t = time(NULL);
    to = localtime(&t);
    strftime(current_time, sizeof(current_time), "%Y/%m/%d-%H:%M:%S", to);

    printf("%s: %s[%s]\n", current_time, header, msg);
    return;
}

// HIDDEN FILE DETECTING START
int read_dev_file(const char *file_name)
{
    struct stat statbuf;

    if (lstat(file_name, &statbuf) < 0) {
        return (-1);
    }

    /* Process directories recursively */
    if (S_ISDIR(statbuf.st_mode)) {
        //mtdebug2(ARGV0, "Reading dir: %s\n", file_name);
        return (read_dev_dir(file_name));
    }

    else if (S_ISREG(statbuf.st_mode)) {
        char op_msg[OS_SIZE_1024 + 1];

        snprintf(op_msg, OS_SIZE_1024, "File '%s' present on /dev. Possible hidden file.", file_name);
        notify_rk(ROOTKIT_ALERT, op_msg);

        _dev_errors++;
    }

    return (0);
}

int read_dev_dir(const char *dir_name)
{
    int i;
    DIR *dp;
    struct dirent *entry = NULL;
    char f_name[PATH_MAX + 2];
    char f_dir[PATH_MAX + 2];

    /* When will these people learn that /dev is not
     * meant to store log files or other kind of texts?
     */
    const char *(ignore_dev[]) = {"MAKEDEV", "README.MAKEDEV",
                                  "MAKEDEV.README", ".udevdb",
                                  ".udev.tdb", ".initramfs-tools",
                                  "MAKEDEV.local", ".udev", ".initramfs",
                                  "oprofile", "fd", "cgroup",
                                  NULL
                                 };

    /* Full path ignore */
    const char *(ignore_dev_full_path[]) = {"shm/sysconfig",
                                            "bus/usb/.usbfs",
                                            "shm",
                                            "gpmctl",
                                            NULL
                                           };

    if (dir_name == NULL || strlen(dir_name) > PATH_MAX) {
        //mterror(ARGV0, "Invalid directory given.");
        return (-1);
    }

    /* Open directory */
    dp = opendir(dir_name);
    if (!dp) {
        return (-1);
    }

    /* Iterate over all files in the directory */
    while ((entry = readdir(dp)) != NULL) {
        /* Ignore . and ..  */
        if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        _dev_total++;

        /* Do not look for the ignored files */
        for (i = 0; ignore_dev[i] != NULL; i++) {
            if (strcmp(ignore_dev[i], entry->d_name) == 0) {
                break;
            }
        }
        if (ignore_dev[i] != NULL) {
            continue;
        }

        *f_name = '\0';
        snprintf(f_name, PATH_MAX + 1, "%s/%s", dir_name, entry->d_name);

        /* Do not look for the full ignored files */
        for (i = 0; ignore_dev_full_path[i] != NULL; i++) {
            snprintf(f_dir, PATH_MAX + 1, "%s/%s", dir_name, ignore_dev_full_path[i]);
            if (strcmp(f_dir, f_name) == 0) {
                break;
            }
        }

        /* Check against the full path */
        if (ignore_dev_full_path[i] != NULL) {
            continue;
        }

        /* Found a non-ignored entry in the directory, so process it */
        read_dev_file(f_name);
    }

    closedir(dp);
    return (0);
}

void check_rc_dev(const char *basedir)
{
    char file_path[OS_SIZE_1024 + 1];

    _dev_total = 0, _dev_errors = 0;
    //mtdebug1(ARGV0, "Starting on check_rc_dev");

    snprintf(file_path, OS_SIZE_1024, "%s/dev", basedir);

    read_dev_dir(file_path);
    if (_dev_errors == 0) {
        char op_msg[OS_SIZE_1024 + 1];
        snprintf(op_msg, OS_SIZE_1024, "No problem detected on the /dev "
                 "directory. Analyzed %d files",
                 _dev_total);
        notify_rk(ROOTKIT_ALERT, op_msg);
    }

    return;
}

int read_sys_file(const char *file_name, int do_read)
{
    struct stat statbuf;

    _sys_total++;

    if (lstat(file_name, &statbuf) < 0) {

        char op_msg[OS_SIZE_1024 + 1];
        snprintf(op_msg, OS_SIZE_1024, "Anomaly detected in file '%s'. "
                 "Hidden from stats, but showing up on readdir. "
                 "Possible kernel level rootkit.",
                 file_name);
        notify_rk(ROOTKIT_ALERT, op_msg);
        _sys_errors++;

        return (-1);
    }
    /* If directory, read the directory */
    else if (S_ISDIR(statbuf.st_mode)) {
        if (strstr(file_name, "/dev/fd") != NULL) {
            return (0);
        }

        /* Ignore the /proc directory (it has size 0) */
        if (statbuf.st_size == 0) {
            return (0);
        }

        return (read_sys_dir(file_name, do_read));
    }

    /* Check if the size from stats is the same as when we read the file */
    if (S_ISREG(statbuf.st_mode) && do_read) {
        char buf[OS_SIZE_1024];
        int fd;
        ssize_t nr;
        long int total = 0;

        fd = open(file_name, O_RDONLY, 0);

        /* It may not necessarily open */
        if (fd >= 0) {
            while ((nr = read(fd, buf, sizeof(buf))) > 0) {
                total += nr;
            }
            close(fd);

            if (strcmp(file_name, "/dev/bus/usb/.usbfs/devices") == 0) {
                /* Ignore .usbfs/devices */
            } else if (total != statbuf.st_size) {
                struct stat statbuf2;

                if ((lstat(file_name, &statbuf2) == 0) &&
                        (total != statbuf2.st_size) &&
                        (statbuf.st_size == statbuf2.st_size)) {
                    char op_msg[OS_SIZE_1024 + 1];
                    snprintf(op_msg, OS_SIZE_1024, "Anomaly detected in file "
                             "'%s'. File size doesn't match what we found. "
                             "Possible kernel level rootkit.",
                             file_name);
                    notify_rk(ROOTKIT_ALERT, op_msg);
                    _sys_errors++;
                }
            }
        }
    }

    return (0);
}

int read_sys_dir(const char *dir_name, int do_read)
{
    int i = 0;
    unsigned int entry_count = 0;
    int did_changed = 0;
    DIR *dp;
    struct dirent *entry = NULL;
    struct stat statbuf;
    short is_nfs;
    short skip_fs;

    //printf("Dir name = %s\n", dir_name);

    const char *(dirs_to_doread[]) = { "/bin", "/sbin", "/usr/bin",
                                       "/usr/sbin", "/dev", "/etc",
                                       "/boot", NULL
                                     };

    if ((dir_name == NULL) || (strlen(dir_name) > PATH_MAX)) {
        printf("Invalid directory given.\n");
        return (-1);
    }

    if(lstat(dir_name, &statbuf) < 0)
    {
        return(-1);
    }

    /* Current device id */
    dev_t did = 0;
    if (did != statbuf.st_dev) {
        if (did != 0) {
            did_changed = 1;
        }
        did = statbuf.st_dev;
    }

    if (!S_ISDIR(statbuf.st_mode)) {
        //printf("DEBUG1=\n");
        return (-1);
    }

    /* Check if the do_read is valid for this directory */
    while (dirs_to_doread[i]) {
        //printf("i==%d, %s\n", i, dirs_to_doread[i]);
        if (strcmp(dir_name, dirs_to_doread[i]) == 0) {
            do_read = 1;
                //printf("DEBUG2=%s\n", dir_name);
            break;
        }
        i++;
    }

    //printf("DEBUG3=\n");
    /* Open the directory */
    dp = opendir(dir_name);
    if (!dp) {
        //printf("DEBUG4=\n");
        if ((strcmp(dir_name, "") == 0) && (dp = opendir("/"))) 
        {
        
        } 
        else {
            //printf("DEBUG5=\n");
            return (-1);
        }
    }
    //printf("DEBUG6=\n");

    /* Read every entry in the directory */
    while ((entry = readdir(dp)) != NULL) {
        //printf("DEBUG7  =\n");
        char f_name[PATH_MAX + 2];
        struct stat statbuf_local;

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) 
        {
            entry_count++;
            continue;
        }

        /* Create new file + path string */
        if (strlen(dir_name) == 1 && *dir_name == PATH_SEP) {
            snprintf(f_name, PATH_MAX + 1, "%c%s", PATH_SEP, entry->d_name);
        } else {
            snprintf(f_name, PATH_MAX + 1, "%s%c%s", dir_name, PATH_SEP, entry->d_name);
        }

        //printf("DEBUG8  =\n");
        /* Check if file is a directory */
        if (lstat(f_name, &statbuf_local) == 0) {
            if (S_ISDIR(statbuf_local.st_mode))
                if (S_ISDIR(statbuf_local.st_mode) || S_ISREG(statbuf_local.st_mode) || S_ISLNK(statbuf_local.st_mode))
                {
                    entry_count++;
                }
            }
        /* Ignore the /proc and /sys filesystems */
        //if (check_ignore(f_name) || !strcmp(f_name, "/proc") || !strcmp(f_name, "/sys")) {
        if (!strcmp(f_name, "/proc") || !strcmp(f_name, "/sys")) {
        	printf("proc or sys exit\n");
            continue;
        }

        read_sys_file(f_name, do_read);
    }

    // printf("DEBUG 20\n");
    // printf("entry count=%d\n", entry_count);
    // printf("did_changed=%d\n", did_changed);
    // printf("st_nlink=%d\n", statbuf.st_nlink);

    if ((entry_count != (unsigned) statbuf.st_nlink) && ((did_changed == 0) || ((entry_count + 1) != (unsigned) statbuf.st_nlink))) 
    {
        struct stat statbuf2;
        char op_msg[OS_SIZE_1024 + 1];

        if ((lstat(dir_name, &statbuf2) == 0) && ((unsigned) statbuf2.st_nlink != entry_count)) 
        {
            //printf("DEBUG 22\n");
            snprintf(op_msg, OS_SIZE_1024, "Files hidden inside directory'%s'. Link count does not match number of files(%d,%d)."
                ,dir_name, entry_count, (int)statbuf.st_nlink);
            notify_rk(ROOTKIT_ALERT, op_msg);
        }
    }
    closedir(dp);

    return (0);
}
// HIDDEN FILE DETECTING END

// HIDDEN PROCESS DETECTING START
char *get_process_name(int pid)
{
    FILE *fp;
    char path[2048];
    char command[2048];

    sprintf(command, "cat /proc/%d/cmdline", pid);
    /* Open the command for reading. */
    fp = popen(command, "r");
    if (fp == NULL) {
        //printf("Failed to run command\n" );
        //exit(1);
        return NULL;
    }

    /* Read the output a line at a time - output it. */
    while (fgets(path, sizeof(path), fp) != NULL) {
        //printf("%s", path);
        pclose(fp);
        return path;
    }

    /* close */
    pclose(fp);
    return NULL;
}

/* Check if a file exists */
int is_file(char *file)
{
    FILE *fp;
    fp = fopen(file, "r");
    if (fp) {
        fclose(fp);
        return (1);
    }
    return (0);
}

/* Check if 'file' is present on 'dir' using readdir */
int isfile_ondir(const char *file, const char *dir)
{
    DIR *dp = NULL;
    struct dirent *entry = NULL;
    dp = opendir(dir);

    if (!dp) {
        return (0);
    }

    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, file) == 0) {
            closedir(dp);
            return (1);
        }
    }

    closedir(dp);
    return (0);
}

/* If /proc is mounted, check to see if the pid is present */
int proc_read(int pid)
{
    char dir[OS_SIZE_1024 + 1];

    if (noproc) {
        return (0);
    }

    snprintf(dir, OS_SIZE_1024, "%d", pid);
    if (isfile_ondir(dir, "/proc")) {
        return (1);
    }
    return (0);
}

/* If /proc is mounted, check to see if the pid is present */
int proc_opendir(int pid)
{
    char dir[OS_SIZE_1024 + 1];
    DIR *dp = NULL;

    if (noproc) {
        return (0);
    }
    
    dp  = opendir("/proc");
    if (!dp) {
        return 0;
    }
    closedir(dp);
    
    snprintf(dir, OS_SIZE_1024, "/proc/%d", pid);
    dp  = opendir(dir);
    if (!dp) {
        return 0;
    }
    closedir(dp);

    return (1);
}

/* If /proc is mounted, check to see if the pid is present there */
int proc_stat(int pid)
{
    char proc_dir[OS_SIZE_1024 + 1];

    if (noproc) {
        return (0);
    }

    snprintf(proc_dir, OS_SIZE_1024, "%s/%d", "/proc", pid);

    if (is_file(proc_dir)) {
        return (1);
    }

    return (0);
}

/* Check all the available PIDs for hidden stuff */
void loop_all_pids(const char *ps, pid_t max_pid, int *_errors, int *_total)
{
    int _kill0 = 0;
    int _kill1 = 0;
    int _gsid0 = 0;
    int _gsid1 = 0;
    int _gpid0 = 0;
    int _gpid1 = 0;
    int _ps0 = -1;
    int _proc_stat  = 0;
    int _proc_read  = 0;
    int _proc_opendir = 0;

    pid_t i = 1;
    pid_t my_pid;

    char command[OS_SIZE_1024 + 64];

    my_pid = getpid();

    for (;; i++) {
        //printf("LOOP %d\n", i);
        if ((i <= 0) || (i > max_pid)) {
            break;
        }

        (*_total)++;

        _kill0 = 0;
        _kill1 = 0;
        _gsid0 = 0;
        _gsid1 = 0;
        _gpid0 = 0;
        _gpid1 = 0;
        _ps0 = -1;

        /* kill test */
        if (!((kill(i, 0) == -1) && (errno == ESRCH))) {
            _kill0 = 1;
        }

        /* getsid test */
        if (!((getsid(i) == -1) && (errno == ESRCH))) {
            _gsid0 = 1;
        }

        /* getpgid test */
        if (!((getpgid(i) == -1) && (errno == ESRCH))) {
            _gpid0 = 1;
        }

        /* /proc test */
        _proc_stat = proc_stat(i);
        _proc_read = proc_read(i);
        _proc_opendir = proc_opendir(i);

        /* If PID does not exist, move on */
        if (!_kill0 && !_gsid0 && !_gpid0 &&
                !_proc_stat && !_proc_read && !_proc_opendir) {
            continue;
        }

        /* Ignore our own pid */
        if (i == my_pid) {
            continue;
        }

        /* Check the number of errors */
        if ((*_errors) > 15) {
            char op_msg[OS_SIZE_1024 + 1];
            snprintf(op_msg, OS_SIZE_1024, "Excessive number of hidden processes"
                     ". It maybe a false-positive or "
                     "something really bad is going on.");
            notify_rk(SYSTEM_CRIT, op_msg);
            return;
        }

        /* Check if the process appears in ps(1) output */
        if (*ps) {
            snprintf(command, sizeof(command), "%s -p %d > /dev/null 2>&1", ps, (int)i);
            _ps0 = 0;
            if (system(command) == 0) {
                _ps0 = 1;
            }
        }

        /* If we are run in the context of OSSEC-HIDS, sleep here (no rush) */
        /* Everything fine, move on */
        if (_ps0 && _kill0 && _gsid0 && _gpid0 && _proc_stat && _proc_read) {
            continue;
        }

        /*
         * If our kill or getsid system call got the PID but ps(1) did not,
         * find out if the PID is deleted (not used anymore)
         */
        if (!((getsid(i) == -1) && (errno == ESRCH))) {
            _gsid1 = 1;
        }
        if (!((kill(i, 0) == -1) && (errno == ESRCH))) {
            _kill1 = 1;
        }
        if (!((getpgid(i) == -1) && (errno == ESRCH))) {
            _gpid1 = 1;
        }

        _proc_stat = proc_stat(i);
        _proc_read = proc_read(i);
        _proc_opendir = proc_opendir(i);

        /* If it matches, process was terminated in the meantime, so move on */
        if (!_gsid1 && !_kill1 && !_gpid1 && !_proc_stat &&
                !_proc_read && !_proc_opendir) {
            continue;
        }
        /* Ignore AIX wait and sched programs */
        if (_gsid0 == _gsid1 &&
            _kill0 == _kill1 &&
            _gpid0 == _gpid1 &&
            _ps0 == 1 &&
            _gsid0 == 1 &&
            _kill0 == 0) {
                continue;
        }

        if (_gsid0 == _gsid1 &&
                _kill0 == _kill1 &&
                _gsid0 != _kill0) {
            /* If kill worked, but getsid and getpgid did not, it may
             * be a defunct process -- ignore.
             */
            if (! (_kill0 == 1 && _gsid0 == 0 && _gpid0 == 0 && _gsid1 == 0) ) {
                char op_msg[OS_SIZE_1024 + 1];

                snprintf(op_msg, OS_SIZE_1024, "Process ID = '%d', NAME = '%s'. is hidden from "
                         "kill (%d) or getsid (%d). Possible kernel-level"
                         " rootkit.", (int)i, get_process_name((int)i), _kill0, _gsid0);
                notify_rk(ROOTKIT_ALERT, op_msg);
                (*_errors)++;
            }
        } else if (_kill1 != _gsid1 ||
                   _gpid1 != _kill1 ||
                   _gpid1 != _gsid1) {
            /* See defunct process comment above */
            if (! (_kill1 == 1 && _gsid1 == 0 && _gpid0 == 0) ) {
                char op_msg[OS_SIZE_1024 + 1];

                snprintf(op_msg, OS_SIZE_1024, "Process ID = '%d', NAME = '%s'. is hidden from "
                         "kill (%d), getsid (%d) or getpgid. Possible "
                         "kernel-level rootkit.", (int)i, get_process_name((int)i), _kill1, _gsid1);
                notify_rk(ROOTKIT_ALERT, op_msg);
                (*_errors)++;
            }
        } else if (_proc_read != _proc_stat  ||
                   _proc_read != _proc_opendir ||
                   _proc_stat != _kill1) {
            /* Check if the pid is a thread (not showing in /proc */
            if (!noproc && !check_rc_readproc((int)i)) {
                char op_msg[OS_SIZE_1024 + 1];

                snprintf(op_msg, OS_SIZE_1024, "Process ID = '%d', NAME = '%s'. is hidden from "
                         "/proc. Possible kernel level rootkit.", (int)i, get_process_name((int)i));
                notify_rk(ROOTKIT_ALERT, op_msg);
                (*_errors)++;
            }
        } else if (_gsid1 && _kill1 && !_ps0) {
            /* checking if the pid is a thread (not showing on ps */
            if (!check_rc_readproc((int)i)) {
                char op_msg[OS_SIZE_1024 + 1];

                snprintf(op_msg, OS_SIZE_1024, "Process ID = '%d', NAME = '%s'. is hidden from "
                         "ps. Possible trojaned version installed.",
                         (int)i, get_process_name((int)i));
                notify_rk(ROOTKIT_ALERT, op_msg);
                (*_errors)++;
            }
        }
    }
}

/* Scan the whole filesystem looking for possible issues */
void check_rc_pids()
{
    int _total = 0;
    int _errors = 0;

    char ps[OS_SIZE_1024 + 1];

    char proc_0[] = "/proc";
    char proc_1[] = "/proc/1";

    pid_t max_pid = MAX_PID;
    noproc = 1;

    /* Checking where ps is */
    memset(ps, '\0', OS_SIZE_1024 + 1);
    strncpy(ps, "/bin/ps", OS_SIZE_1024);
    if (!is_file(ps)) {
        strncpy(ps, "/usr/bin/ps", OS_SIZE_1024);
        if (!is_file(ps)) {
            ps[0] = '\0';
        }
    }

    /* Proc is mounted */
    if (is_file(proc_0) && is_file(proc_1)) {
        noproc = 0;
    }

    loop_all_pids(ps, max_pid, &_errors, &_total);

    if (_errors == 0) {
        char op_msg[OS_SIZE_2048];
        snprintf(op_msg, OS_SIZE_2048, "No hidden process by Kernel-level "
                 "rootkits.\n      %s is not trojaned. "
                 "Analyzed %d processes.", ps, _total);
        notify_rk(ROOTKIT_ALERT, op_msg);
    }

    return;
}

/////////////////
int read_proc_file(const char *file_name, const char *pid, int position)
{
    struct stat statbuf;

    if (lstat(file_name, &statbuf) < 0) {
        return (-1);
    }

    /* If directory, read the directory */
    if (S_ISDIR(statbuf.st_mode)) {
        return (read_proc_dir(file_name, pid, position));
    }

    return (0);
}

int read_proc_dir(const char *dir_name, const char *pid, int position)
{
    DIR *dp;
    struct dirent *entry = NULL;

    if ((dir_name == NULL) || (strlen(dir_name) > PATH_MAX)) {
        //mterror(ARGV0, "Invalid directory given");
        return (-1);
    }

    /* Open the directory */
    dp = opendir(dir_name);
    if (!dp) {
        return (0);
    }

    while ((entry = readdir(dp)) != NULL) {
        char f_name[PATH_MAX + 2];

        /* Ignore . and ..  */
        if (strcmp(entry->d_name, ".")  == 0 ||
                strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (position == PROC) {
            char *tmp_str;

            tmp_str = entry->d_name;
            while (*tmp_str != '\0') {
                if (!isdigit((int)*tmp_str)) {
                    break;
                }
                tmp_str++;
            }

            if (*tmp_str != '\0') {
                continue;
            }

            snprintf(f_name, PATH_MAX + 1, "%s/%s", dir_name, entry->d_name);
            read_proc_file(f_name, pid, position + 1);
        } else if (position == PID) {
            if (strcmp(entry->d_name, "task") == 0) {
                snprintf(f_name, PATH_MAX + 1, "%s/%s", dir_name, entry->d_name);
                read_proc_file(f_name, pid, position + 1);
            }
        } else if (position == TASK) {
            /* Check under proc/pid/task/lwp */
            if (strcmp(entry->d_name, pid) == 0) {
                proc_pid_found = 1;
                break;
            }
        } else {
            break;
        }
    }

    closedir(dp);

    return (0);
}

/*  Read the /proc directory (if present) and check if it can find
 *  the given pid (as a pid or as a thread)
 */
int check_rc_readproc(int pid)
{
    char char_pid[32];

    proc_pid_found = 0;

    /* NL threads */
    snprintf(char_pid, 31, "/proc/.%d", pid);
    if (is_file(char_pid)) {
        return (1);
    }

    snprintf(char_pid, 31, "%d", pid);
    read_proc_dir("/proc", char_pid, PROC);

    return (proc_pid_found);
}


void main(int argc, char *argv[])
{
    printf("This is the start of the hidden file monitoring...\n");
    
    const char *(dirs_to_scan[]) = {"bin", "sbin", "usr/bin",
                                "usr/sbin", "dev", "lib",
                                "etc", "root", "var/log",
                                "var/mail", "var/lib", "var/www",
                                "usr/lib", "usr/include",
                                "tmp", "boot", "usr/local",
                                "var/tmp", "sys", NULL
                               };
    int _i = 0;
    char dir_path[1024];
    while (dirs_to_scan[_i] != NULL) {
        snprintf(dir_path, OS_SIZE_1024, "%c%s", PATH_SEP, dirs_to_scan[_i]);
        read_sys_dir(dir_path, 0);
        _i++;
    }

    check_rc_dev("");

    printf("\nThis is the start of the hidden process monitoring...\n");

    check_rc_pids();
}