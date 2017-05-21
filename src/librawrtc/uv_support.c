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

void *rawrtc_mem_zalloc(size_t size, rawrtc_mem_destroy_h *dh)
{
	return mem_zalloc(size, (mem_destroy_h *)dh);
}

int rawrtc_alloc_fds(int maxfds)
{
	return alloc_fds(maxfds);
}

void rawrtc_dbg_init(int level, enum dbg_flags flags)
{
	return dbg_init(level, flags);
}

struct mbuf *rawrtc_mbuf_alloc(size_t size)
{
	return mbuf_alloc(size);
}

int rawrtc_mbuf_printf(struct mbuf *mb, const char *fmt)
{
	return mbuf_printf(mb, fmt);
}

void rawrtc_mbuf_set_pos(struct mbuf *mb, size_t pos)
{
	return mbuf_set_pos(mb, pos);
}

size_t rawrtc_mbuf_get_left(const struct mbuf *mb)
{
	return mbuf_get_left(mb);
}

void rawrtc_list_unlink(struct le *le) {
	return list_unlink(le);
}

uint8_t *rawrtc_mbuf_buf(const struct mbuf *mb)
{
	return mbuf_buf(mb);
}

int rawrtc_mbuf_fill(struct mbuf *mb, uint8_t c, size_t n)
{
	return mbuf_fill(mb, c, n);
}

size_t rawrtc_mbuf_get_space(const struct mbuf *mb)
{
	return mbuf_get_space(mb);
}
