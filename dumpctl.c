/*
 * Provide a storage and retreval mechanism for system coredumps similar to systemd-coredump, but without the requirement on using systemd
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>

/* LOG_* levels */
#include <syslog.h>

/* getopt */
#include <unistd.h>

/* mkdir */
#include <sys/stat.h>
#include <sys/types.h>

/* opendir */
#include <dirent.h>

#include <errno.h>

/* strftime */
#include <time.h>

/* uintmax_t, strtoumax() */
#include <inttypes.h>

/* openat */
#include <fcntl.h>

#include <sys/prctl.h>

#ifndef CFG_CORE_LIMIT
#define CFG_CORE_LIMIT (1024 * 1024 * 1024)
#endif

/*
 * We don't use any threads or signals, so try using the unlocked_stdio operations
 */
#define fread fread_unlocked
#define feof feof_unlocked
#define fwrite fwrite_unlocked
#define ferror ferror_unlocked
#define fileno fileno_unlocked
#define fflush fflush_unlocked


#define STR_(x) #x
#define STR(x) STR_(x)

/* WE MUST NOT FAIL with something that would trigger us again, so use a
 * hand-rolled assert that exits */
#define assert(x) do { \
	if (!(x)) { \
		pr_err("assert failed: %s:%s : %s\n", __FILE__, STR(__LINE__), #x); \
		exit(EXIT_FAILURE); \
	} \
} while(0)

/* Try to get a bit more info. Unfortunately we're handicapped by our inability
 * to select a function based on the type of a value effectively (we could try
 * using _Generic, but it would be a bunch of work and not allow easy
 * extensibility).
 */
#define assert_cmp(left, cmp, right) do { \
	__typeof__(left) __assert_cmp_left = (left); \
	__typeof__(right) __assert_cmp_right = (right); \
	if (!(__assert_cmp_left cmp __assert_cmp_right)) { \
		pr_err("assert failed: %s:%s : %s %s %s -> %jd %s %jd\n", \
				__FILE__, STR(__LINE__), \
				#left, #cmp, #right, \
				(uintmax_t)__assert_cmp_left, #cmp, (uintmax_t)__assert_cmp_right); \
	} \
} while(0)

#ifndef CFG_COREDUMP_PATH
# define CFG_COREDUMP_PATH "/var/lib/systemd/coredump"
#endif
static
const char *default_path = CFG_COREDUMP_PATH;

static
const char *opts = ":hd:";
#define PRGMNAME_DEFAULT "dumpctl"

static bool err_include_level = false;
static int kmsg_fd = -1;

static
void usage_(const char *prgmname, int e)
{
	FILE *f;
	if (e != EXIT_SUCCESS)
		f = stderr;
	else
		f = stdout;
	fprintf(f,
"Usage: %s [options] <action-and-args...>\n"
"       %s [options] store <global-pid> <uid> <gid> <signal-number> <unix-timestamp> <-%%c?-> <executable-filename> <exe-path>\n"
"       %s [options] setup\n"
"       %s [options] list\n"
"       %s [options] info\n"
"       %s [options] gdb\n"
"\n"
"Use me to handle your coredumps:\n"
"    # echo '|%s store %%P %%u %%g %%s %%t %%c %%e %%E' | /proc/sys/kernel/core_pattern\n"
"Or, run:\n"
"    # %s store-setup\n"
"\n"
"Options: -[%s]\n"
"  -d <directory>     store the coredumps in this directory\n"
"                     default = '%s'\n"
		, prgmname, prgmname, prgmname, prgmname, prgmname, prgmname, prgmname, prgmname, opts, default_path);

	exit(e);
}
#define usage(e) usage_(prgmname, e)

__attribute__((format(printf,1,2)))
static void
pr_log(const char fmt[static 3], ...)
{
	va_list ap;
	/* XXX: consider whether stdout is appropriate sometimes */
	const char *f = fmt;
	if (!err_include_level)
		f+=3;
	va_start(ap, fmt);
	vfprintf(stderr, f, ap);
	va_end(ap);
}

#define PR_LOG(lvl, ...) pr_log("<" STR(lvl) ">" PRGMNAME_DEFAULT ": " __VA_ARGS__)

#define pr_emerg(...) PR_LOG(LOG_EMERG, __VA_ARGS__)
#define pr_alert(...) PR_LOG(LOG_ALERT, __VA_ARGS__)
#define pr_crit(...) PR_LOG(LOG_CRIT, __VA_ARGS__)
#define pr_err(...) PR_LOG(LOG_ERR, __VA_ARGS__)
#define pr_warn(...) PR_LOG(LOG_WARNING, __VA_ARGS__)
#define pr_notice(...) PR_LOG(LOG_NOTICE, __VA_ARGS__)
#define pr_info(...) PR_LOG(LOG_INFO, __VA_ARGS__)
#define pr_debug(...) PR_LOG(LOG_DEBUG, __VA_ARGS__)

struct fbuf {
	size_t bytes_in_buf;
	uint8_t buf[4096];
};

static void *fbuf_space_ptr(struct fbuf *f)
{
	return f->buf + f->bytes_in_buf;
}

static size_t fbuf_space(struct fbuf *f)
{
	return sizeof(f->buf) - f->bytes_in_buf;
}

static void fbuf_feed(struct fbuf *f, size_t n)
{
	assert_cmp(fbuf_space(f), <=, n);
	f->bytes_in_buf += n;
}

static void *fbuf_data_ptr(struct fbuf *f)
{
	return f->buf;
}

static size_t fbuf_data(struct fbuf *f)
{
	return f->bytes_in_buf;
}

static void fbuf_eat(struct fbuf *f, size_t n)
{
	assert(n <= fbuf_data(f));
	memmove(f->buf, f->buf + n, f->bytes_in_buf - n);
	f->bytes_in_buf -= n;
}

static void fbuf_init(struct fbuf *f)
{
	/* NOTE: for perf, we do not zero the buffer */
	f->bytes_in_buf = 0;
}

static
uintmax_t parse_unum(const char *n, const char *name)
{
	char *end;
	errno = 0;
	uintmax_t v = strtoumax(n, &end, 0);
	if (v == UINTMAX_MAX && errno) {
		fprintf(stderr, "Error: failure parsing %s, '%s': %s\n", name, n, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (*end != '\0') {
		fprintf(stderr, "Error: trailing characters in %s, '%s'\n", name, n);
		exit(EXIT_FAILURE);
	}

	return v;
}

enum act {
	ACT_NONE,
	ACT_SETUP,
	ACT_STORE,
	ACT_INFO,
	ACT_GDB,
	ACT_LIST,
};

static enum act parse_act(const char *action)
{
	switch (action[0]) {
	case 's':
		switch (action[1]) {
		case 'e':
			return ACT_SETUP;
		case 't':
			return ACT_STORE;
		default:
			return ACT_NONE;
		}
		break;
	case 'g':
		return ACT_GDB;
	case 'l':
		return ACT_LIST;
	case 'i':
		return ACT_INFO;
	default:
		return ACT_NONE;
	}
}

/*
 * Copy from a FILE * to an fd, trying to avoid blocking too much.
 * We might be able to improve this by using threads or async io.
 */
static ssize_t copy_file_to_fd(int out_fd, FILE *in_file)
{
	size_t read_bytes = 0;
	size_t written_bytes = 0;
	unsigned err = 0;
	bool done_reading = false;
	/* TODO: replace this with a magic ring buffer */
	struct fbuf f;
	fbuf_init(&f);

	for (;;) {
		if (err > 10) {
			pr_err("too many errors while copying file");
			return -1;
		}

		size_t rl = fread(fbuf_space_ptr(&f), 1, fbuf_space(&f), in_file);
		if (rl == 0) {
			if (feof(in_file)) {
				/* done reading! */	
				done_reading = true;
			} else {
				pr_warn("Error reading input core file\n");
				err++;
				continue;
			}
		}
		fbuf_feed(&f, rl);
		read_bytes += rl;
		//pr_info("read %zu bytes (%zu total)\n", rl, read_bytes);

		do {
			if (fbuf_data(&f) == 0) {
				return written_bytes;
			}

			ssize_t wl = write(out_fd, fbuf_data_ptr(&f), fbuf_data(&f));
			if (wl == 0) {
				/* ??? */
				fprintf(stderr, "write returned zero bytes written, will retry\n");
				err++;
				break;
			}

			if (wl < 0) {
				fprintf(stderr, "write failed due to %s\n", strerror(errno));
				err++;
				break;
			}

			fbuf_eat(&f, wl);
			written_bytes += wl;
			//pr_info("write %zd bytes (%zu total)\n", wl, written_bytes);

		/* if we've go space to read, do that again. If not, keep trying to write */
		} while (fbuf_space(&f) == 0 || done_reading);

		if (read_bytes >= CFG_CORE_LIMIT) {
			pr_warn("not storing core, too large\n");
			return -1;
		}
	}
}

static int act_store(char *dir, int argc, char *argv[])
{
	int err = 0;
	if (argc != 8 && argc != 9) {
		pr_err("store requires 8 or 9 arguments, got %d\n", argc);
		err++;
	}

	/* for store, we require an absolute path */
	if (dir[0] != '/') {
		pr_err("store requires an absolute path, but got '%s'\n", dir);
		err++;
	}

	if (err)
		exit(EXIT_FAILURE);

	/* FIXME: allow these to be non-fatal errors */
	uintmax_t pid = parse_unum(argv[1], "pid"),
		  uid = parse_unum(argv[2], "uid"),
		  gid = parse_unum(argv[3], "gid"),
		  sig = parse_unum(argv[4], "signal"),
		  ts  = parse_unum(argv[5], "timestamp");
	/* +6 = core limit */
	const char *comm = argv[7];

	/* FIXME: path gotten this way is mangled... for some reason. unmangle.
	 * Also check if this can be confused (by embedded whitespace or other
	 * junk */
	char *path = argv[8];

	pr_alert("'%s' aborted with signal %ju (pid = %ju, uid = %ju, path = %s)\n",
			comm, sig, pid, uid, path);

	/* create our storage area if it does not exist */
	/* for each component in path, mkdir() */
	char *p = dir + 1;
	for (;;) {
		p = strchr(p, '/');
		if (p)
			*p = '\0';

		int r = mkdir(dir, 0777);
		if (r == -1) {
			if (errno != EEXIST) {
				pr_err("could not create path '%s', mkdir failed: %s\n",
						dir, strerror(errno));
				exit(EXIT_FAILURE);
			}
		}

		if (!p)
			break;
		*p = '/';
		p = p + 1;
	}

	DIR *d = opendir(dir);
	if (!d) {
		pr_err("failed to open storage dir '%s', opendir failed: %s\n",
				dir, strerror(errno));
		exit(EXIT_FAILURE);
	}
	struct tm tm;
	/* FIXME: check overflow */
	time_t ts_time = ts;
	gmtime_r(&ts_time, &tm);

	/* try to use 'YYYY-MM-DD_HH:MM:SS.pid=PID.uid=UID' */

	char path_buf[PATH_MAX];
	size_t b = strftime(path_buf, sizeof(path_buf), "%F_%H:%M:%S", &tm);
	if (b == 0) {
		pr_err("strftime failed\n");
		exit(EXIT_FAILURE);
	}

	p = path_buf + b;
	int r = snprintf(p, sizeof(path_buf) - b, ".pid=%ju.uid=%ju", pid, uid);
	if (r < 0) {
		pr_err("could not format storage path\n");
		exit(EXIT_FAILURE);
	}

	if ((size_t)r > (sizeof(path_buf) - b - 1)) {
		pr_err("formatted storage path too long (needed %u bytes)\n", r);
		exit(EXIT_FAILURE);
	}

	/* XXX: consider making this a temp dir before we fill in the data */
	r = mkdirat(dirfd(d), path_buf, 0755);
	if (r < 0) {
		/* XXX: handle directory collisions when many things fail near each other in time */
		pr_err("failed to create dump directory: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	int store_fd = openat(dirfd(d), path_buf, O_DIRECTORY, 0755);
	if (store_fd == -1) {
		pr_err("could not open storage dir '%s', %s\n", path_buf, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* store some data! */
	int core_fd = openat(store_fd, "core", O_CREAT|O_WRONLY, 0644);
	if (core_fd == -1) {
		pr_err("could not open core file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	r = copy_file_to_fd(core_fd, stdin);
	if (r < 0) {
		/* error printing already handled, just avoid storage */
		unlinkat(store_fd, "core", 0);
	}

	close(core_fd);

	int info_fd = openat(store_fd, "info.txt", O_CREAT|O_WRONLY, 0644);
	if (info_fd == -1) {
		pr_err("could not open info.txt file: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	dprintf(info_fd,
			"pid: %ju\n"
			"uid: %ju\n"
			"gid: %ju\n"
			"signal: %ju\n"
			"timestamp: %ju\n"
			"comm: %s\n"
			"path: %s\n",
		pid, uid, gid, sig, ts, comm, path);

	close(info_fd);

	return 0;
}

static int act_setup(const char *self)
{
	char path[PATH_MAX + 1];
	ssize_t n = readlink("/proc/self/exe", path, sizeof(path) -1);
	if (n == -1) {
		pr_warn("could not read /proc/self/exe: %s\n", strerror(errno));
		pr_notice("falling back to using argv[0]\n");
		/* If `self` is not complete & absolute, we neet to convert it to be so */
		char *resolved_path = realpath(self, path);
		if (!resolved_path) {
			pr_err("Error: failed to determined real path: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	} else {
		/* "Conforming applications should not assume that the returned
		 * contents of the symbolic link are null-terminated" */
		path[n] = '\0';
	}

	pr_info("registering using path '%s'\n", path);

	FILE *f = fopen("/proc/sys/kernel/core_pattern", "w");
	if (!f) {
		pr_err("could not open /proc/sys/kernel/core_pattern file to configure system: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	int r = fprintf(f, "| %s store %%P %%u %%g %%s %%t %%c %%e %%E", path);
	if (r <= 0) {
		pr_err("failed to write to core_pattern (but open worked): %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	fclose(f);
	return 0;
}

static bool fd_is_open(int fd)
{
	off_t r = lseek(fd, 0, SEEK_CUR);
	return r != -1 || errno != EBADF;
}

int main(int argc, char *argv[])
{
        /* Make sure we never enter a loop */
        (void) prctl(PR_SET_DUMPABLE, 0);

	/*
	 * When we're started by the kernel for 'store', we don't have the stdout & stderr filedescriptors open!
	 */
	kmsg_fd = open("/dev/kmsg", O_RDWR);
	/* FIXME: fallback for kmsg open failure? */
	/*
	 * for our sanity, let's use kmsg as our output if we don't have
	 * something hooked up. This nicely means we do "the right thing" when
	 * the kernel is executing us directly.
	 *
	 * XXX: zero error checking here. not a good thing.
	 * XXX: the open() of kmsg_fd prior to this might fill in one of these!
	 */
	if (kmsg_fd == STDOUT_FILENO || kmsg_fd == STDERR_FILENO)
		err_include_level = true;
	if (!fd_is_open(STDOUT_FILENO)) {
		err_include_level = true;
		dup2(kmsg_fd, STDOUT_FILENO);
	}
	if (!fd_is_open(STDERR_FILENO)) {
		err_include_level = true;
		dup2(kmsg_fd, STDERR_FILENO);
	}

	/* XXX: can we detect early if we're recursing on ourselves? Being
	 * called recursively is an easy way to use all system resources */

	char *dir = strdup(default_path);
	const char *prgmname = argc?argv[0]:PRGMNAME_DEFAULT;
	
	int err = 0;
	int opt;

	while ((opt = getopt(argc, argv, opts)) != -1) {
		switch (opt) {
		case 'd':
			free(dir);
			dir = strdup(optarg);
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		case '?':
			err++;
			break;
		default:
			fprintf(stderr, "Error: programmer screwed up argument -%c\n", opt);
			err++;
			break;
		}
	}


	if (argc == optind) {
		err++;
		fprintf(stderr, "Error: an action is required but none was found\n");
		usage(EXIT_FAILURE);
	}

	const char *action = argv[optind];
	enum act act = parse_act(action);
	if (act == ACT_NONE) {
		err++;
		fprintf(stderr, "Error: unknown action '%s'\n", action);
	}

	if (err)
		usage(EXIT_FAILURE);

	argc -= optind;
	argv += optind;
	switch (act) {
	case ACT_STORE:
		return act_store(dir, argc, argv);
	case ACT_SETUP:
		return act_setup(prgmname);
	default:
		pr_warn("action %s is unimplimented\n", action);
		exit(EXIT_FAILURE);
		;
	}

	return 0;		
}
