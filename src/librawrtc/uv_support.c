#include "rawrtc_internal.h"
#include "debug.h"

void rawrtc_set_uv_loop(uv_loop_t *loop)
{
    external_loop_set(LOOP_UV, loop);
}

/*  Wrapper functions needed by NEAT */

void *rawrtc_mem_deref(void *data)
{
	return mem_deref(data);
}

void *rawrtc_mem_zalloc(size_t size, rawrtc_mem_destroy_h *dh)
{
	return mem_zalloc(size, (mem_destroy_h *)dh);
}

void *rawrtc_mem_ref(void *data)
{
	return mem_ref(data);
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

int rawrtc_mbuf_write_mem(struct mbuf *mb, const uint8_t *buf, size_t size)
{
	return mbuf_write_mem(mb, buf, size);
}

void rawrtc_list_unlink(struct le *le)
{
	return list_unlink(le);
}

uint32_t rawrtc_list_count(const struct list *list)
{
	return list_count(list);
}

struct le *rawrtc_list_head(const struct list *list)
{
	return list_head(list);
}

void rawrtc_list_flush(struct list *list)
{
	return list_flush(list);
}

void rawrtc_list_append(struct list *list, struct le *le, void *data)
{
	return list_append(list, le, data);
}

void rawrtc_list_init(struct list *list)
{
	return list_init(list);
}

void *rawrtc_list_ledata(const struct le *le)
{
	return list_ledata(le);
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

int rawrtc_fd_listen(int fd, int flags, fd_h *fh, void *arg)
{
	return fd_listen(fd, flags, fh, arg);
}

int rawrtc_odict_alloc(struct odict **op, uint32_t hash_size) {
	return odict_alloc(op, hash_size);
}

int rawrtc_odict_entry_add(struct odict *o, const char *key, enum odict_type type, va_list argp)
{
	/*va_list args;
	va_start(args, type);
	int err = odict_entry_add(o, key, type, args);
	va_end(args);
	return err;*/
	return odict_entry_add(o, key, type, argp);
}

int rawrtc_json_encode_odict(struct re_printf *pf, const struct odict *o)
{
	return json_encode_odict(pf, o);
}

int rawrtc_json_decode_odict(struct odict **op, uint32_t hash_size, const char *str,
		                     size_t len, unsigned maxdepth)
{
	return json_decode_odict(op, hash_size, str, len, maxdepth);
}

const struct odict_entry *rawrtc_odict_lookup(const struct odict *o, const char *key)
{
	return odict_lookup(o, key);
}

void rawrtc_dbg_info(const char *fmt, va_list argp)
{
	/*va_list args;
	va_start(args, fmt);
	dbg_info(fmt, args);
	va_end(args);*/
	dbg_info(fmt, argp);
}

