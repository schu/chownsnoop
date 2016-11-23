#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

typedef struct {
	u32 pid;
	uid_t uid;
	gid_t gid;
	int ret;
	char filename[256];
} chown_event_t;

BPF_PERF_OUTPUT(chown_events);
BPF_HASH(chowncall, u64, chown_event_t);

int kprobe__sys_fchownat(struct pt_regs *ctx, int dfd, const char *filename,
		         uid_t uid, gid_t gid, int flag)
{
	u64 pid = bpf_get_current_pid_tgid();
	chown_event_t event = {
		.pid = pid >> 32,
		.uid = uid,
		.gid = gid,
	};
	bpf_probe_read(&event.filename, sizeof(event.filename), (void *)filename);
	chowncall.update(&pid, &event);
	return 0;
}

int kretprobe__sys_fchownat(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	chown_event_t *eventp = chowncall.lookup(&pid);
	if (eventp == 0) {
		return 0;
	}
	chown_event_t event = *eventp;
	event.ret = ret;
	chown_events.perf_submit(ctx, &event, sizeof(event));
	chowncall.delete(&pid);
	return 0;
}
