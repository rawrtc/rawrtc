#include "rawrtc_internal.h"
#include "debug.h"

void rawrtc_set_uv_loop(uv_loop_t *loop)
{
    external_loop_set(LOOP_UV, loop);
}

void *rawrtc_mem_deref(void *data)
{
	return mem_deref(data);
}

int rawrtc_alloc_fds(int maxfds)
{
	return alloc_fds(maxfds);
}

void rawrtc_dbg_init(int level, enum dbg_flags flags)
{
	return dbg_init(level, flags);
}

/*void rawrtc_clear_timer_handles()
{
	clear_handle_list();
}*/
