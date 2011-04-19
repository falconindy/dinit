#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

/* util-linux */
#include <blkid.h>

#define msg(...) {if (!quiet) fprintf(stderr, ":: " __VA_ARGS__);}
#define err(...) {fprintf(stderr, "error" __VA_ARGS__);}
#define die(...) {err(__VA_ARGS__); _exit(1);}

#define TMPFS_FLAGS   MS_NOEXEC|MS_NODEV|MS_NOSUID
#define NEWROOT       "/new_root"
#define UDEVD_PATH    "/sbin/udevd"
#define CMDLINE_SIZE  2048       /* from arch/x86/include/asm/setup.h */

int rootflags = 0;
int quiet = 0;

/* utility */
static void forkexecwait(char **argv) { /* {{{ */
  pid_t pid;
  int statloc;

  pid = fork();
  if (pid == -1) {
    perror("fork");
    return;
  }

  if (pid == 0) {
    int errsv;
    execv(argv[0], argv);
    errsv = errno;
    fprintf(stderr, "failed to launch %s\n", argv[0]);
    errno = errsv;
    perror("");
  }

  /* block for process exit */
  waitpid(pid, &statloc, 0);

  return;
} /* }}} */

static char *concat_path(const char *path, const char *filename) { /* {{{ */
  const char *ss, *lc;
  char *concat;
  int ret;

  if (!path) {
    path = "";
  }

  for (ss = path; *ss; ss++);
  lc = (*--ss == '/' ? "" : "/");

  while (*filename == '/') {
    filename++;
  }

  ret = asprintf(&concat, "%s%s%s", path, lc, filename);
  if (ret < 0) {
    return NULL;
  }

  return concat;
} /* }}} */

static char *sanitize_var(char *var) { /* {{{ */
  char *p;

  p = var;
  if (!(isalpha(*p) || *p == '_')) {
    /* invalid var name, can't use this */
    return NULL;
  }

  p++;
  while (*p) {
    switch (*p) {
      case '-': /* fallthrough */
      case '.':
        *p = '_';
        break;
      case '=': /* don't touch anything past this */
        return var;
    }
    p++;
  }

  return var;
} /* }}} */

static void delete_contents(const char *directory, dev_t rootdev) { /* {{{ */
  DIR *dir;
  struct dirent *d;
  struct stat st;

  /* Don't descend into other filesystems */
  if (lstat(directory, &st) || st.st_dev != rootdev) {
    return;
  }

  /* Recursively delete the contents of directories */
  if (S_ISDIR(st.st_mode)) {
    dir = opendir(directory);
    if (dir) {
      while ((d = readdir(dir))) {
        char *newdir = d->d_name;

        /* Skip . and .. */
        if (strcmp(newdir, ".") == 0 || strcmp(newdir, "..") == 0) {
          continue;
        }

        /* Recurse to delete contents */
        newdir = concat_path(directory, newdir);
        delete_contents(newdir, rootdev);
        free(newdir);
      }
      closedir(dir);

      /* Directory should now be empty, zap it */
      rmdir(directory);
    }
  } else {
    /* It wasn't a directory, zap it */
    unlink(directory);
  }
} /* }}} */

static void start_rescue_shell(void) { /* {{{ */
  char *bboxinstall[] = { "/bin/busybox", "--install", NULL };
  char *bboxlaunch[] = { "/bin/busybox", "ash", NULL };

  /* install symlinks */
  forkexecwait(bboxinstall);

  /* set a prompt */
  putenv("PS1=[ramfs \\W]\\$ ");

  /* start the shell */
  forkexecwait(bboxlaunch);

} /* }}} */

static char *probe_fstype(const char *devname) { /* {{{ */
  int ret;
  char *fstype;
  blkid_probe pr;

  pr = blkid_new_probe_from_filename(devname);
  if (!pr) {
    err("%s: failed to create a new libblkid probe\n", devname);
    return NULL;
  }

  blkid_probe_enable_superblocks(pr, 1);
  blkid_probe_set_superblocks_flags(pr, BLKID_SUBLKS_TYPE);

  ret = blkid_do_safeprobe(pr);
  if (ret == -1) {
    return NULL;
  } else if (ret == 1) {
    err("failed to probe device %s\n", devname);
    return NULL;
  } else {
    const char *name, *data;
    blkid_probe_get_value(pr, 0, &name, &data, NULL);
    fstype = strdup(data);
  }

  blkid_free_probe(pr);

  return fstype;
} /* }}} */

/* meat */
static void mount_setup(void) { /* {{{ */
  int ret;

  /* setup basic filesystems */
  mount("proc", "/proc", "proc", TMPFS_FLAGS, NULL);
  mount("sys", "/sys", "sysfs", TMPFS_FLAGS, NULL);
  mount("tmpfs", "/run", "tmpfs", TMPFS_FLAGS, "mode=1777,size=10M");

  /* mountpoint for our eventual real root */
  mkdir(NEWROOT, 0755);

  /* ENODEV returned on non-existant FS */
  ret = mount("udev", "/dev", "devtmpfs", MS_NOSUID, "mode=0755,size=10M");
  if (ret == -1 && errno == ENODEV) {
    /* devtmpfs not available, use standard tmpfs */
    mount("udev", "/dev", "tmpfs", MS_NOSUID, "mode=0755,size=10M");

    /* create necessary nodes
     * crw------- 1 root root 5, 1 Apr  2 18:30 /dev/console
     * crw-rw-rw- 1 root root 1, 3 Apr  2 18:30 /dev/null
     * crw-rw-rw- 1 root root 1, 5 Apr  2 18:30 /dev/zero
     */
    mknod("/dev/console", S_IFCHR|0600, makedev(5, 1));
    mknod("/dev/null", S_IFCHR|0666, makedev(1, 3));
    mknod("/dev/zero", S_IFCHR|0666, makedev(1, 5));
  }
} /* }}} */

static void put_cmdline(void) { /* {{{ */
  char cmdline[CMDLINE_SIZE], token[CMDLINE_SIZE];
  char quoted = '\0';
  char *c, *tp;
  int isvar = 0;
  FILE *fp;

  /* a bit of pointer/var hell going on...
   *   c = pointer along contents of /proc/cmdline
   *   token = container for current token being parsed
   *   tp = pointer along contents of token
   */

  fp = fopen("/proc/cmdline", "r");
  if (!fp) {
    return;
  }

  if (!fgets(cmdline, CMDLINE_SIZE, fp)) {
    return;
  }
  fclose(fp);

  tp = token;
  for (c = cmdline; *c; c++) {
    if (*c == '#') { /* full stop! */
      break;
    }

    if (isspace((unsigned char)*c)) {
      /* don't break inside a quoted region */
      if (!quoted && tp != token) {
        *tp = '\0';
        if (sanitize_var(token)) {
          if (isvar) {
            putenv(strdup(token));
          } else {
            setenv(strdup(token), "y", 1);
          }
          if (strcmp(token, "ro") == 0) {
            rootflags |= MS_RDONLY;
          } else if (strcmp(token, "quiet") == 0) {
            quiet = 1;
          }
        }
        isvar = 0;
        tp = token;
      }
      continue;
    } else if (*c == '\'' || *c == '"') {
      if (quoted) {
        if (quoted == *c) {
          quoted = '\0';
          continue;
        }
      } else {
        quoted = *c;
        continue;
      }
    }

    if (*c == '=') {
      isvar = 1;
    }

    *tp++ = *c;
  }
} /* }}} */

static void disable_modules(void) { /* {{{ */
  char *tok, *var;
  FILE *fp;

  if (getenv("disablemodules") == NULL) {
    return;
  }

  /* ensure parent dirs exist */
  mkdir("/etc", 0755);
  mkdir("/etc/modprobe.d", 0755);

  fp = fopen("/etc/modprobe.d/initcpio.conf", "w");
  if (!fp) {
    perror("error: /etc/modprobe.d/initcpio.conf");
    return;
  }

  var = strdup(getenv("disablemodules"));
  for (tok = strtok(var, ","); tok; tok = strtok(NULL, ",")) {
    fprintf(fp, "install %s /bin/false\n", tok);
  }

  fclose(fp);
  free(var);
} /* }}} */

static pid_t launch_udev(void) { /* {{{ */
  char *udev_argv[] = { UDEVD_PATH, UDEVD_PATH, "--resolve-names=never", NULL };
  pid_t pid;

  if (access(UDEVD_PATH, X_OK) != 0) {
    return 0;
  }

  msg("Starting udev...\n");

  pid = fork();
  if (pid == -1) {
    perror("fork");
    return 1;
  }

  if (pid == 0) {
    execv(UDEVD_PATH, udev_argv);
    perror("exec: " UDEVD_PATH);
  }

  return pid;
} /* }}} */

static void load_extra_modules(void) { /* {{{ */
  FILE *fp;
  char *tok, *var;
  char **argv;
  char line[PATH_MAX];
  int modcount = 2;

  /* load early modules */
  if (getenv("earlymodules") != NULL) {
    argv = calloc(2, sizeof(argv));
    *argv = "/sbin/modprobe";
    *(argv + 1) = "-qa";

    var = strdup(getenv("earlymodules"));
    for (tok = strtok(var, ","); tok; tok = strtok(NULL, ",")) {
      argv = realloc(argv, sizeof(argv) * ++modcount);
      *(argv + (modcount - 1)) = tok;
    }

    if (modcount > 2) {
      argv = realloc(argv, sizeof(argv) * ++modcount);
      *(argv + (modcount - 1)) = NULL;
      forkexecwait(argv);
    }
    free(argv);
  }

  /* load modules from /config */
  fp = fopen("/config", "r");
  if (fp) {
    while (fgets(line, PATH_MAX, fp) != NULL) {
      if (strncmp(line, "MODULES=", 8) == 0) {
        argv = calloc(2, sizeof(argv));
        *argv = "/sbin/modprobe";
        *(argv + 1) = "-qa";
        modcount = 2;

        for (tok = strtok(&line[9], " \"\n"); tok; tok = strtok(NULL, " \"\n")) {
          argv = realloc(argv, sizeof(argv) * ++modcount);
          *(argv + (modcount - 1)) = tok;
        }

        /* make sure array wasn't empty */
        if (modcount > 2) {
          argv = realloc(argv, sizeof(argv) * ++modcount);
          *(argv + (modcount - 1)) = NULL;
          forkexecwait(argv);
        }

        free(argv);
        break;
      }
    }
    fclose(fp);
  }

} /* }}} */

static void trigger_udev_events(void) { /* {{{ */
  char *argv[] = { "/sbin/udevadm", "trigger", "--action=add", NULL };

  msg("triggering udev events...\n");
  forkexecwait(argv);
} /* }}} */

static void disable_hooks(void) { /* {{{ */
  char *hook, *list, *disable;

  disable = getenv("disablehooks");
  if (!disable) {
    return;
  }

  list = strdup(disable);
  for (hook = strtok(list, ", "); hook; hook = strtok(NULL, ", ")) {
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/hooks/%s", hook);

    /* mark as non-executable so run_hooks skips over it */
    chmod(path, 0644);
  }

  free(list);
} /* }}} */

static void run_hooks(void) { /* {{{ */
  FILE *fp;
  char line[PATH_MAX];
  char *hook;

  fp = fopen("/config", "r");
  if (!fp) {
    return;
  }

  while (fgets(line, PATH_MAX, fp) != NULL) {
    if (strncmp(line, "HOOKS=", 6) != 0) {
      continue;
    }

    for (hook = strtok(&line[6], " \"\n"); hook; hook = strtok(NULL, " \"\n")) {
      char path[PATH_MAX];

      snprintf(path, 4096, "hooks/%s", hook);

      if (access(path, X_OK) != 0) {
        continue;
      }

      char *argv[] = { path, path, NULL };
      forkexecwait(argv);
    }
  }
} /* }}} */

static void wait_for_root(void) { /* {{{ */
  char *rootdelay, *root;
  int found = 0, delay = 0;

  rootdelay = getenv("rootdelay");
  if (rootdelay) {
    delay = atoi(rootdelay);
  }

  if (delay == 0) {
    delay = 10;
  }

  root = getenv("root");

  msg("waiting up to %d seconds for %s ...\n", delay, root);
  while (delay--) {
    if (access(root, R_OK) == 0) {
      found = 1;
      break;
    }
    sleep(1);
  }

  if (!found) {
    err("root didn't show up! You are on your own, good luck\n");
    start_rescue_shell();
    msg("continuing... this will probably fail\n");
  }

} /* }}} */

static void mount_root(void) { /* {{{ */
  char *root, *fstype;
  struct stat st;

  root = getenv("root");
  if (!root) {
    err("root is undefined!\n");
    return;
  }

  if (stat(root, &st) != 0) {
    err("failed to stat root!\n");
    return;
  }

  fstype = probe_fstype(root);
  if (!fstype) {
    /* should never reach this */
    err("zomg unknown FS!\n");
    return;
  }

  if (mount(root, NEWROOT, fstype, rootflags, NULL) != 0) {
    err("failed to mount new root!\n");
  }
  free(fstype);
} /* }}} */

static char *find_init(void) { /* {{{ */
  char *init;
  char path[PATH_MAX];

  init = getenv("init");
  if (!init) {
    init = "/sbin/init";
  }

  snprintf(path, PATH_MAX, NEWROOT "%s", init);
  if (access(path, R_OK) != 0) {
    err("root is mounted, but '%s' is not found! Bailing to a rescue shell."
        "Good luck!\n", init);
    start_rescue_shell();
    err("continuing... \n");
  }

  return init;
} /* }}} */

static void kill_udev(pid_t pid) { /* {{{ */
  char path[PATH_MAX];
  char *exe;

  if (pid <= 1) { /* error launching udev */
    return;
  }

  snprintf(path, PATH_MAX, "/proc/%d/exe", pid);
  exe = realpath(path, NULL);

  if (strcmp(exe, UDEVD_PATH) == 0) {
    kill(pid, SIGTERM);
  }

  free(exe);
} /*}}}*/

static int switch_root(char *argv[]) { /* {{{ */
  struct stat st;
  struct statfs stfs;
  dev_t rootdev;

  /* this is mostly taken from busybox's util_linux/switch_root.c */

  /* Change to new root directory and verify it's a different fs */
  chdir(NEWROOT);
  stat("/", &st); 
  rootdev = st.st_dev;
  stat(".", &st);

  if (st.st_dev == rootdev) {
    die("nothing was mounted on " NEWROOT "!\n");
  }

  /* Additional sanity checks: we're about to rm -rf /, so be REALLY SURE we
   * mean it. I could make this a CONFIG option, but I would get email from all
   * the people who WILL destroy their filesystems. */
  if (stat("/init", &st) != 0 || !S_ISREG(st.st_mode)) {
    err("/init not found or not a regular file\n");
    start_rescue_shell();
  }

  statfs("/", &stfs); /* this never fails */
  if ((unsigned)stfs.f_type != RAMFS_MAGIC &&
      (unsigned)stfs.f_type != TMPFS_MAGIC) {
    die("root filesystem is not ramfs/tmpfs\n");
  }

  /* zap everything out of rootdev */
  delete_contents("/", rootdev);

  /* mount $PWD over / and chroot into it */
  if (mount(".", "/", NULL, MS_MOVE, NULL) != 0) {
    /* fails when newroot is not a mountpoint */
    die("error moving root\n");
  }
  chroot(".");

  /* The chdir is needed to recalculate "." and ".." links */
  chdir("/");

  /* redirect stdin/stdout/stderr to new console */
  close(0);
  open("/dev/console", O_RDWR);
  dup2(0, 1);
  dup2(0, 2);

  /* exec real pid shady */
  execv(argv[0], argv);
  err("failed to execute '%s'\n", argv[0]);
  fprintf(stderr, ":: This is the end. Something has gone terribly wrong.\n"
                  ":: Please file a detailed bug report.\n");
  _exit(EXIT_FAILURE);
} /* }}} */

int main(int argc, char *argv[]) {
  char *init;
  pid_t udevpid;

  (void)argc; /* poor unloved argc */

  /* need some actual error checking throughout here */

  mount_setup();             /* create early tmpfs mountpoints */
  put_cmdline();             /* parse cmdline and set environment */
  disable_modules();         /* blacklist modules passed in on cmdline */
  udevpid = launch_udev();   /* try to launch udev */
  load_extra_modules();      /* load modules passed in on cmdline */
  trigger_udev_events();     /* read and process uevent queue */
  disable_hooks();           /* delete hooks specified on cmdline */
  run_hooks();               /* run remaining hooks */
  wait_for_root();           /* ensure that root shows up */
  mount_root();              /* this better work... */
  init = find_init();        /* mounted something, now find init */
  kill_udev(udevpid);        /* shutdown udev in prep switch_root  */

  /* move mount points (fstype, options and flags are ignored) */
  mount("/proc", NEWROOT "/proc", NULL, MS_MOVE,  NULL);
  mount("/sys", NEWROOT "/sys", NULL, MS_MOVE, NULL);
  mount("/run", NEWROOT "/run", NULL, MS_MOVE, NULL);

  argv[0] = init;
  switch_root(argv);
  /* unreached */
  return 0;
}

/* vim: set et ts=2 sw=2 */
