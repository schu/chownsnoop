#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <bcc/bpf_common.h>
#include <bcc/libbpf.h>
#include <bcc/perf_reader.h>

#define NUM_CPUS 8

typedef struct {
	uint32_t pid;
	uint32_t uid;
	uint32_t gid;
	int ret;
	char filename[256];
} chown_event_t;

void callback(void *cookie, void *raw, int raw_size) {
	chown_event_t event = *(chown_event_t*)raw;
	printf("uid %d gid %d pid %d called fchownat(2) on %s (return value: %d)\n",
	       event.uid, event.gid, event.pid, event.filename, event.ret);
}

int main(int argc, const char **argv) {
	int kprobe_fd, kretprobe_fd, reader_fd, table_fd, i, key, res;
	char logbuf[8192];
	const char *cflags[] = {
		"-DNUMCPUS=8"
	};
	const char *kprobe_name = "kprobe__sys_fchownat",
	           *kretprobe_name = "kretprobe__sys_fchownat",
	            *module_file = "./chownsnoop.c";
	void *m = NULL, *kprobe = NULL;
	struct perf_reader *perf_readers[NUM_CPUS], *reader;
	struct bpf_insn *kprobe_start = NULL, *kretprobe_start = NULL;

	/*
	 * Create a new BPF module object from the code in the module file.
	 */
	m = bpf_module_create_c(module_file, 2, cflags, 1);
	if (m == NULL) {
		fprintf(stderr, "failed to create bpf module\n");
		return 1;
	}

	/*
	 * Get the start of the BPF program.
	 */
	kprobe_start = bpf_function_start(m, kprobe_name);
	if (kprobe_start == NULL) {
		fprintf(stderr, "unable to get kprobe start %s\n", kprobe_name);
		goto on_error;
	}

	/*
	 * Load the BPF program as BPF_PROG_TYPE_KPROBE.
	 */
	kprobe_fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, kprobe_start,
			          bpf_function_size(m, kprobe_name),
				  bpf_module_license(m),
	                          bpf_module_kern_version(m),
				  logbuf, sizeof(logbuf));
	if (kprobe_fd < 0) {
		fprintf(stderr, "unable to get kprobe fd (got CAP_SYS_ADMIN?): %s\n", strerror(errno));
		if (strlen(logbuf) > 0) {
			fprintf(stderr, "%s\n", logbuf);
		};
		goto on_error;
	}

	/*
	 * Attach the loaded program as kprobe to sys_fchownat.
	 * https://www.kernel.org/doc/Documentation/trace/kprobetrace.txt
	 */
	kprobe = bpf_attach_kprobe(kprobe_fd, "p_sys_fchownat",
			           "p:kprobes/p_sys_fchownat sys_fchownat",
				   -1, 0, -1, NULL, NULL);
	if (kprobe == NULL) {
		fprintf(stderr, "failed to attach kprobe\n");
		goto on_error;
	}


	/*
	 * Same procedure for loading the kretprobe ...
	 */

	kretprobe_start = bpf_function_start(m, kretprobe_name);
	if (kretprobe_start == NULL) {
		fprintf(stderr, "unable to get kretprobe start %s\n", kretprobe_name);
		goto on_error;
	}

	kretprobe_fd = bpf_prog_load(BPF_PROG_TYPE_KPROBE, kretprobe_start,
	                             bpf_function_size(m, kretprobe_name),
				     bpf_module_license(m),
				     bpf_module_kern_version(m),
				     logbuf, sizeof(logbuf));
	if (kretprobe_fd < 0) {
		fprintf(stderr, "unable to get kretprobe fd (got CAP_SYS_ADMIN?): %s\n", strerror(errno));
		if (strlen(logbuf) > 0) {
			fprintf(stderr, "%s\n", logbuf);
		};
		goto on_error;
	}

	kprobe = bpf_attach_kprobe(kretprobe_fd, "r_sys_fchownat",
			           "r:kprobes/r_sys_fchownat sys_fchownat",
				   -1, 0, -1, NULL, NULL);
	if (kprobe == NULL) {
		fprintf(stderr, "failed to attach kretprobe\n");
		goto on_error;
	}

	/*
	 * Get a fd for the output table (chown_events).
	 */
	table_fd = bpf_table_fd_id(m, 0);
	if (table_fd < 0) {
		fprintf(stderr, "failed to get table fd\n");
		goto on_error;
	}

	/*
	 * Open a perf buffer for each CPU.
	 */
	for (i=0, key=0,res=0; i<NUM_CPUS && res==0; i++) {
		reader = bpf_open_perf_buffer(&callback, NULL, -1, i);
		if (reader == NULL) {
			fprintf(stderr, "failed to open perf buffer %d\n", i);
			goto on_error;
		}

		perf_readers[i] = reader;
		reader_fd = perf_reader_fd(reader);

		res = bpf_update_elem(table_fd, &key, &reader_fd, 0);
		if (res != 0) {
			fprintf(stderr, "failed to update perf map entry %d (%d)\n", i, res);
			goto on_error;
		}

		res = bpf_get_next_key(table_fd, &key, &key);
	}

	/*
	 * Poll for events on all readers.
	 */
	for (;;) {
		perf_reader_poll(NUM_CPUS, perf_readers, -1);
	}

	bpf_module_destroy(m);
	return 0;

on_error:
	bpf_module_destroy(m);
	return 1;
}
