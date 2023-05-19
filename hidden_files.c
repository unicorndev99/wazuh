

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
//#define     PATH_MAX        2048
#define     OS_SIZE_1024    1024

#define     ROOTKIT_ALERT   "INFO: "
#define     SYSTEM_CRIT     "WARN: "

/* Global variables */
static int   _sys_errors;
static int   _sys_total;
static dev_t did;

static int _dev_errors;
static int _dev_total;

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
                if (S_ISDIR(statbuf_local.st_mode) || S_ISREG(statbuf_local.st_mode) || S_ISLNK(statbuf_local.st_mode))//s_isreg check that is it a regular file
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
}