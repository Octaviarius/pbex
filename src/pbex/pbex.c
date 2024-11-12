#include "pbex.h"

#include <stdlib.h>

#ifdef PBEX_EXTERNAL_INCLUDE
#include PBEX_EXTERNAL_INCLUDE
#endif

#ifndef PBEX_ATOMIC_BEGIN
#define PBEX_ATOMIC_BEGIN()
#endif

#ifndef PBEX_ATOMIC_END
#define PBEX_ATOMIC_END()
#endif

#ifndef PBEX_DL_ALLOCATOR_DOUBLE_LINKED
#define PBEX_DL_ALLOCATOR_DOUBLE_LINKED 0
#endif

/**
 * \addtogroup Internal
 * \{
 */

#define OFFSET_OF(type, member)         ((size_t)(uintptr_t) & ((type*)0)->member)
#define CONTAINER_OF(ptr, type, member) (*(type*)((char*)(ptr)-OFFSET_OF(type, member)))

#define ALIGN(val, size)                (((val) + (size)-1) & ~((size)-1))

/** Internal representation of list node */
struct pbex_list_node
{
    pbex_list_node_t* next;   //!< Pointer to next node
    uint8_t           data[]; //!< Payload
};

/** Encode string callback when \ref pbex_alloc_string is used */
static bool _encode_string(pb_ostream_t* stream, const pb_field_t* field, void* const* arg);
/** Encode string callback when \ref pbex_set_string is used */
static bool _encode_string_static(pb_ostream_t* stream, const pb_field_t* field, void* const* arg);
/** Encode C-string callback when \ref pbex_set_cstring is used */
static bool _encode_cstring_static(pb_ostream_t* stream, const pb_field_t* field, void* const* arg)
/** Encode string callback when \ref pbex_alloc_bytes is used */
static bool _encode_bytes(pb_ostream_t* stream, const pb_field_t* field, void* const* arg);
/** Encode bytes callback when \ref pbex_set_bytes is used */
static bool _encode_bytes_static(pb_ostream_t* stream, const pb_field_t* field, void* const* arg);
/** Encode list callback when \ref pbex_alloc_list is used */
static bool _encode_list(pb_ostream_t* stream, const pb_field_t* field, void* const* arg);

/** Decode string callback */
static bool _decode_string(pb_istream_t* stream, const pb_field_t* field, void** arg);
/** Decode bytes callback */
static bool _decode_bytes(pb_istream_t* stream, const pb_field_t* field, void** arg);
/** Decode oneof fields callback */
static bool _decode_oneof(pb_istream_t* stream, const pb_field_t* field, void** arg);
/** Decode repeated fields callback */
static bool _decode_repeated(pb_istream_t* stream, const pb_field_t* field, void** arg);

/** Calculates actual structure size just using descriptor */
static size_t _prepare_size_of_struct(const pb_msgdesc_t* descr);
/** Makes preparations before run decode */
static bool _prepare_decode(pbex_allocator_t* allocator, pb_istream_t* stream, const pb_msgdesc_t* descr, void* inst);

/**
 * \}
 */

static bool _encode_string(pb_ostream_t* stream, const pb_field_t* field, void* const* arg)
{
    const pbex_string_t* d = (const pbex_string_t*)(*arg);

    if (d)
    {
        if (pb_encode_tag_for_field(stream, field))
        {
            return pb_encode_string(stream, (pb_byte_t*)d->data, d->size - 1);
        }
    }

    return false;
}

static bool _encode_string_static(pb_ostream_t* stream, const pb_field_t* field, void* const* arg)
{
    return _encode_string(stream, field, arg);
}

static bool _encode_cstring_static(pb_ostream_t* stream, const pb_field_t* field, void* const* arg)
{
    const char* d = (const char*)(*arg);

    if (d)
    {
        if (pb_encode_tag_for_field(stream, field))
        {
            return pb_encode_string(stream, (pb_byte_t*)d, strlen(d));
        }
    }

    return false;
}

static bool _encode_bytes(pb_ostream_t* stream, const pb_field_t* field, void* const* arg)
{
    const pbex_bytes_t* d = (const pbex_bytes_t*)(*arg);

    if (d)
    {
        if (pb_encode_tag_for_field(stream, field))
        {
            return pb_encode_string(stream, (pb_byte_t*)d->data, d->size);
        }
    }

    return false;
}

static bool _encode_bytes_static(pb_ostream_t* stream, const pb_field_t* field, void* const* arg)
{
    return _encode_bytes(stream, field, arg);
}

static bool _encode_list(pb_ostream_t* stream, const pb_field_t* field, void* const* arg)
{
    const pbex_list_t* d = (const pbex_list_t*)(*arg);

    if (d)
    {
        pbex_list_node_t* node = d->head;

        while (node)
        {
            if (!pb_encode_tag_for_field(stream, field))
            {
                return false;
            }

            if (!pb_encode_submessage(stream, field->submsg_desc, node->data))
            {
                return false;
            }

            node = node->next;
        }

        return true;
    }

    return false;
}

//-----------------------------------------------

static bool _decode_string(pb_istream_t* stream, const pb_field_t* field, void** arg)
{
    (void)field;

    pbex_allocator_t* allocator = (pbex_allocator_t*)(*arg);
    if (!allocator)
    {
        return false;
    }

    pbex_string_t** dd = (pbex_string_t**)arg;
    *dd                = (pbex_string_t*)allocator->alloc(allocator, sizeof(pbex_string_t) + stream->bytes_left + 1);
    if (*dd == NULL)
    {
        return false;
    }

    pbex_string_t* d = *dd;

    d->size = stream->bytes_left + 1;

    if (!pb_read(stream, (pb_byte_t*)d->data, stream->bytes_left))
    {
        allocator->dealloc(allocator, d);
        *arg = NULL;
        return false;
    }

    d->data[d->size - 1] = '\0';

    return true;
}

static bool _decode_bytes(pb_istream_t* stream, const pb_field_t* field, void** arg)
{
    (void)field;

    pbex_allocator_t* allocator = (pbex_allocator_t*)(*arg);
    if (!allocator)
    {
        return false;
    }

    pbex_bytes_t** dd = (pbex_bytes_t**)arg;
    *dd               = (pbex_bytes_t*)allocator->alloc(allocator, sizeof(pbex_bytes_t) + stream->bytes_left);
    if (*dd == NULL)
    {
        return false;
    }

    pbex_bytes_t* d = *dd;

    d->size = stream->bytes_left;

    if (!pb_read(stream, (pb_byte_t*)d->data, stream->bytes_left))
    {
        allocator->dealloc(allocator, d);
        *arg = NULL;
        return false;
    }

    return true;
}

static bool _decode_oneof(pb_istream_t* stream, const pb_field_t* field, void** arg)
{
    pbex_allocator_t* allocator = (pbex_allocator_t*)(*arg);
    if (!allocator)
    {
        return false;
    }

    return _prepare_decode(allocator, stream, field->submsg_desc, field->pData);
}

static bool _decode_repeated(pb_istream_t* stream, const pb_field_t* field, void** arg)
{
    pbex_list_t* list = (pbex_list_t*)(*arg);

    if (list)
    {
        pbex_list_node_t* node = list->allocator->alloc(list->allocator, sizeof(pbex_list_node_t) + list->item_size);

        if (node)
        {
            node->next = NULL;
            if (!list->tail)
            {
                list->tail = list->head = node;
            }
            else
            {
                list->tail->next = node;
                list->tail       = node;
            }

            if (field->submsg_desc->default_value)
            {
                memcpy(&node->data, field->submsg_desc->default_value, list->item_size);
            }

            if (_prepare_decode(list->allocator, stream, field->submsg_desc, &node->data))
            {
                return pb_decode(stream, field->submsg_desc, &node->data);
            }
        }
    }

    return false;
}

#define MSG_PTR ((uint8_t*)sizeof(void*))
static size_t _prepare_size_of_struct(const pb_msgdesc_t* descr)
{
    uint8_t* end_ptr = NULL;

    pb_field_iter_t it;
    pb_field_iter_begin(&it, descr, MSG_PTR);

    do
    {
        uint8_t* end = (uint8_t*)it.pField + it.data_size;
        if (end_ptr < end)
        {
            end_ptr = end;
        }

    } while (pb_field_iter_next(&it));

    return end_ptr - MSG_PTR;
}
#undef MSG_PTR

static bool _prepare_decode(pbex_allocator_t* allocator, pb_istream_t* stream, const pb_msgdesc_t* descr, void* inst)
{
    pb_field_iter_t it;
    pb_field_iter_begin(&it, descr, inst);

    do
    {
        pb_callback_t* callback;

        switch (PB_LTYPE(it.type))
        {
            case PB_LTYPE_STRING:
                callback               = (pb_callback_t*)it.pData;
                callback->funcs.decode = &_decode_string;
                callback->arg          = allocator;
                break;

            case PB_LTYPE_BYTES:
                callback               = (pb_callback_t*)it.pData;
                callback->funcs.decode = &_decode_bytes;
                callback->arg          = allocator;
                break;

            case PB_LTYPE_SUBMESSAGE:
                if (PB_HTYPE(it.type) == PB_HTYPE_REPEATED && PB_ATYPE(it.type) == PB_ATYPE_CALLBACK)
                {
                    pbex_list_t* list = (pbex_list_t*)allocator->alloc(allocator, sizeof(pbex_list_t));

                    if (!list)
                    {
                        return false;
                    }

                    list->allocator = allocator;
                    list->item_size = _prepare_size_of_struct(it.submsg_desc);

                    list->head = NULL;
                    list->tail = NULL;

                    callback               = (pb_callback_t*)it.pData;
                    callback->funcs.decode = &_decode_repeated;
                    callback->arg          = list;

                    break;
                }
                else
                {
                    _prepare_decode(allocator, stream, it.submsg_desc, it.pData);
                }
                break;

            case PB_LTYPE_SUBMSG_W_CB:
                switch (PB_HTYPE(it.type))
                {
                    case PB_HTYPE_ONEOF:
                    {
                        callback               = (pb_callback_t*)it.pSize - 1;
                        callback->funcs.decode = &_decode_oneof;
                        callback->arg          = allocator;
                        break;
                    }
                }
                break;
        }

    } while (pb_field_iter_next(&it));

    return true;
}

//-----------------------------------------------
static bool _ostream_cb_stub(pb_ostream_t* stream, const pb_byte_t* buf, size_t count)
{
    (void)stream;
    (void)buf;
    (void)count;

    return true;
}

pb_ostream_t pbex_create_ostream_stub(void)
{
    pb_ostream_t stream = {0};

    stream.callback = _ostream_cb_stub;
    stream.max_size = SIZE_MAX;

    return stream;
}

//-----------------------------------------------

bool pbex_encode(pb_ostream_t* stream, const pb_msgdesc_t* descr, const void* inst)
{
    if (stream && descr && inst)
    {
        return pb_encode(stream, descr, inst);
    }

    return false;
}

bool pbex_decode(pbex_allocator_t* allocator, pb_istream_t* stream, const pb_msgdesc_t* descr, void* inst)
{
    if (allocator && stream && descr && inst)
    {
        if (_prepare_decode(allocator, stream, descr, inst))
        {
            return pb_decode(stream, descr, inst);
        }
    }

    return false;
}

bool pbex_encode_to_buffer(const pb_msgdesc_t* descr, const void* inst, void* buffer, size_t* size)
{
    if (descr && inst && buffer && size)
    {
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, *size);

        if (pb_encode(&stream, descr, inst))
        {
            *size = stream.bytes_written;
            return true;
        }
        else
        {
            *size = 0;
        }
    }

    return false;
}

bool pbex_encode_to_dynbuffer(const pb_msgdesc_t* descr, const void* inst, void** buffer, size_t* size)
{
    pb_ostream_t stream = pbex_create_ostream_stub();
    bool         ret    = pbex_encode(&stream, descr, inst);

    if (ret)
    {
        *size = stream.bytes_written;

        void* ptr = malloc(*size);

        if (!ptr)
        {
            ret = false;
        }
        else
        {
            *buffer = ptr;
            stream  = pb_ostream_from_buffer(ptr, *size);
            ret     = pbex_encode(&stream, descr, inst);

            if (!ret)
            {
                free(ptr);
            }
        }
    }

    if (!ret)
    {
        *buffer = NULL;
        *size   = 0;
    }

    return ret;
}

bool pbex_decode_from_buffer(pbex_allocator_t*   allocator,
                             const pb_msgdesc_t* descr,
                             void*               inst,
                             const void*         buffer,
                             size_t              size)

{
    pb_istream_t stream = pb_istream_from_buffer(buffer, size);
    bool         ret    = pbex_decode(allocator, &stream, descr, inst);

    return ret;
}

bool pbex_release(pbex_allocator_t* allocator, const pb_msgdesc_t* descr, void* inst)
{
    pb_field_iter_t it;
    pb_field_iter_begin(&it, descr, inst);

    do
    {
        pb_callback_t* callback = NULL;

        switch (PB_LTYPE(it.type))
        {
            case PB_LTYPE_STRING:
            case PB_LTYPE_BYTES:
            {
                callback = (pb_callback_t*)it.pData;
                break;
            }

            case PB_LTYPE_SUBMESSAGE:
                pbex_release(allocator, it.submsg_desc, it.pData);
                break;

            case PB_LTYPE_SUBMSG_W_CB:
            {
                switch (PB_HTYPE(it.type))
                {
                    // WARNING: this is not tested
                    case PB_HTYPE_REPEATED:
                    {
                        callback = (pb_callback_t*)it.pData;

                        if (callback)
                        {
                            pbex_list_t* list = (pbex_list_t*)callback->arg;

                            if (list)
                            {
                                pbex_list_node_t* node = list->head;

                                while (node)
                                {
                                    pbex_release(list->allocator, it.submsg_desc, &node->data);
                                    list->allocator->dealloc(list->allocator, node);
                                    node = node->next;
                                }
                            }
                        }

                        break;
                    }

                    case PB_HTYPE_ONEOF:
                    {
                        callback = (pb_callback_t*)it.pSize - 1;

                        if (callback->arg != allocator && *(pb_size_t*)it.pSize == it.tag)
                        {
                            pbex_release(allocator, it.submsg_desc, it.pData);
                        }
                        break;
                    }
                }

                break;
            }
        }

        // Only if arg is not allocator
        if (callback && callback->arg != allocator)
        {
            if ((void*)&callback->funcs == _decode_bytes || (void*)&callback->funcs == _decode_string
                || (void*)&callback->funcs == _encode_bytes || (void*)&callback->funcs == _encode_string
                || (void*)&callback->funcs == _encode_list || (void*)&callback->funcs == _decode_repeated)
            {
                allocator->dealloc(allocator, callback->arg);
                callback->arg = NULL;
            }
        }

    } while (pb_field_iter_next(&it));

    return true;
}

pb_callback_t pbex_alloc_list(pbex_allocator_t* allocator, size_t item_size)
{
    pbex_list_t* list = allocator->alloc(allocator, sizeof(pbex_list_t));

    if (list)
    {
        list->allocator = allocator;
        list->item_size = item_size;
        list->head      = NULL;
        list->tail      = NULL;

        return (pb_callback_t) {
            .funcs = {.encode = _encode_list},
            .arg   = list,
        };
    }
    else
    {
        return (pb_callback_t) {
            .funcs = {.encode = NULL},
            .arg   = NULL,
        };
    }
}

size_t pbex_list_count(pb_callback_t list)
{
    size_t count = 0;

    pbex_list_t* l = (pbex_list_t*)list.arg;

    PBEX_ATOMIC_BEGIN();

    pbex_list_node_t* node = l->head;

    while (node)
    {
        node = node->next;
        count++;
    }

    PBEX_ATOMIC_END();

    return count;
}

void* pbex_list_add_node(pb_callback_t list)
{
    pbex_list_t* l = (pbex_list_t*)list.arg;

    if (l)
    {
        pbex_list_node_t* node = l->allocator->alloc(l->allocator, sizeof(pbex_list_node_t) + l->item_size);

        if (node)
        {
            node->next = NULL;

            PBEX_ATOMIC_BEGIN();

            if (!l->tail)
            {
                l->tail = l->head = node;
            }
            else
            {
                l->tail->next = node;
                l->tail       = node;
            }

            PBEX_ATOMIC_END();

            return node->data;
        }
    }

    return NULL;
}

void* pbex_list_add_node_after(pb_callback_t list, const void* node)
{
    pbex_list_t* l = (pbex_list_t*)list.arg;

    if (l)
    {
        pbex_list_node_t* new_node = l->allocator->alloc(l->allocator, sizeof(pbex_list_node_t) + l->item_size);

        if (new_node)
        {
            PBEX_ATOMIC_BEGIN();

            pbex_list_node_t* n = &CONTAINER_OF(node, pbex_list_node_t, data);

            new_node->next = n->next;
            n->next        = new_node;

            if (n == l->tail)
            {
                l->tail = new_node;
            }

            PBEX_ATOMIC_END();

            return new_node->data;
        }
    }

    return NULL;
}

void* pbex_list_get_node(pb_callback_t list, size_t idx)
{
    pbex_list_t* l = (pbex_list_t*)list.arg;

    PBEX_ATOMIC_BEGIN();

    pbex_list_node_t* node = l->head;

    while (idx && node)
    {
        node = node->next;
        idx--;
    }

    PBEX_ATOMIC_END();

    return node->data;
}

void* pbex_list_next_node(const void* node)
{
    void* ret = NULL;

    if (node)
    {
        PBEX_ATOMIC_BEGIN();
        pbex_list_node_t* next_node = CONTAINER_OF(node, pbex_list_node_t, data).next;

        if (next_node)
        {
            ret = &next_node->data;
        }
        PBEX_ATOMIC_END();
    }

    return ret;
}

pb_callback_t pbex_alloc_string(pbex_allocator_t* allocator, const char* str, ssize_t len)
{
    if (len < 0)
    {
        if (str)
        {
            len = strlen(str);
        }
        else
        {
            len = 0;
        }
    }

    pbex_string_t* d = (pbex_string_t*)allocator->alloc(allocator, sizeof(pbex_string_t) + len + 1);

    if (d)
    {
        if (str)
        {
            memcpy(d->data, str, len);
        }

        d->data[len] = '\0';

        d->size = len + 1;

        return (pb_callback_t) {
            .funcs = {.encode = _encode_string},
            .arg   = d,
        };
    }
    else
    {
        return (pb_callback_t) {
            .funcs = {.encode = NULL},
            .arg   = NULL,
        };
    }
}

pb_callback_t pbex_set_string(const pbex_string_t* str)
{
    return (pb_callback_t) {
        .funcs = {.encode = _encode_string_static},
        .arg   = (void*)str,
    };
}

pb_callback_t pbex_set_cstring(const char* str)
{
    return (pb_callback_t) {
        .funcs = {.encode = _encode_cstring_static},
        .arg   = (void*)str,
    };
}

const pbex_string_t* pbex_get_string(pb_callback_t callback)
{
    if (callback.funcs.encode == _encode_string || callback.funcs.encode == _encode_string_static)
    {
        return (const pbex_string_t*)callback.arg;
    }
    else if (callback.funcs.decode == _decode_string)
    {
        return (const pbex_string_t*)callback.arg;
    }
    else
    {
        return NULL;
    }
}

bool pbex_get_string_p(pb_callback_t callback, const char** str_ptr, size_t* size_ptr)
{
    const pbex_string_t* str = pbex_get_string(callback);

    if (str)
    {
        if (str_ptr)
        {
            *str_ptr = str->data;
        }

        if (size_ptr)
        {
            *size_ptr = str->size;
        }

        return true;
    }

    return false;
}

const char* pbex_get_cstring(pb_callback_t callback)
{
    const pbex_string_t* str = pbex_get_string(callback);

    if (str)
    {
        return str->data;
    }
    else
    {
        if (callback.funcs.encode == _encode_cstring_static)
        {
            return (const char*)callback.arg;
        }
    }

    return NULL;
}

pb_callback_t pbex_alloc_bytes(pbex_allocator_t* allocator, const void* data, size_t count)
{
    pbex_bytes_t* d = (pbex_bytes_t*)allocator->alloc(allocator, sizeof(pbex_bytes_t) + count);

    if (d)
    {
        d->size = count;

        memcpy(d->data, data, count);

        return (pb_callback_t) {
            .funcs = {.encode = _encode_bytes},
            .arg   = d,
        };
    }
    else
    {
        return (pb_callback_t) {
            .funcs = {.encode = NULL},
            .arg   = NULL,
        };
    }
}

pb_callback_t pbex_set_bytes(const pbex_bytes_t* bytes)
{
    return (pb_callback_t) {
        .funcs = {.encode = _encode_bytes_static},
        .arg   = (void*)bytes,
    };
}

const pbex_bytes_t* pbex_get_bytes(pb_callback_t callback)
{
    if (callback.funcs.encode == _encode_bytes || callback.funcs.encode == _encode_bytes_static)
    {
        return (const pbex_bytes_t*)callback.arg;
    }
    else if (callback.funcs.decode == _decode_bytes)
    {
        return (const pbex_bytes_t*)callback.arg;
    }
    else
    {
        return NULL;
    }
}

bool pbex_get_bytes_p(pb_callback_t callback, const void** data_ptr, size_t* size_ptr)
{
    const pbex_bytes_t* bytes = pbex_get_bytes(callback);

    if (bytes)
    {
        if (data_ptr)
        {
            *data_ptr = bytes->data;
        }

        if (size_ptr)
        {
            *size_ptr = bytes->size;
        }

        return true;
    }

    return false;
}

size_t pbex_copy_bytes_to(pb_callback_t callback, void* data, size_t offset, size_t size)
{
    const pbex_bytes_t* bytes = pbex_get_bytes(callback);

    if (bytes && data && offset < bytes->size)
    {
        if (offset + size > bytes->size)
        {
            size = bytes->size - offset;
        }

        memcpy(data, &bytes->data[offset], size);
        return size;
    }

    return 0;
}

//-----------------------------------------------

static void* _heap_alloc(pbex_allocator_t* self, size_t size)
{
    (void)self;
    return malloc(size);
}

static void _heap_dealloc(pbex_allocator_t* self, void* ptr)
{
    (void)self;
    free(ptr);
}

static void* _pool_alloc(pbex_allocator_t* self, size_t size)
{
    pbex_pool_allocator_t* pool = &CONTAINER_OF(self, pbex_pool_allocator_t, allocator);

    size = ALIGN(size, sizeof(void*));

    PBEX_ATOMIC_BEGIN();

    size_t new_pos = pool->pos + size;

    uint8_t* ptr;
    if (new_pos > pool->size)
    {
        ptr = NULL;
    }
    else
    {
        ptr       = &pool->ptr[pool->pos];
        pool->pos = new_pos;
    }
    PBEX_ATOMIC_END();

    return ptr;
}

static void _pool_dealloc(pbex_allocator_t* self, void* ptr)
{
    // no need to dealloc
    (void)self;
    (void)ptr;
}

typedef struct dl_node dl_node_t;

struct dl_node
{
    dl_node_t* next;
#if PBEX_DL_ALLOCATOR_DOUBLE_LINKED
    dl_node_t* prev;
#endif
    uint8_t data[];
};

static void* _dl_alloc(pbex_allocator_t* self, size_t size)
{
    pbex_dl_allocator_t* dl = &CONTAINER_OF(self, pbex_dl_allocator_t, allocator);

    dl_node_t* new_node = (dl_node_t*)malloc(sizeof(dl_node_t) + size);

    if (new_node)
    {
        dl_node_t* head = (dl_node_t*)&dl->head;

        PBEX_ATOMIC_BEGIN();

#if PBEX_DL_ALLOCATOR_DOUBLE_LINKED
        head->next->prev = new_node;
        new_node->next   = head->next;
        head->next       = new_node;
        new_node->prev   = head;
#else
        new_node->next = head->next;
        head->next     = new_node;
#endif
        PBEX_ATOMIC_END();
        return &new_node->data;
    }

    return NULL;
}

static void _dl_dealloc(pbex_allocator_t* self, void* ptr)
{
    pbex_dl_allocator_t* dl = &CONTAINER_OF(self, pbex_dl_allocator_t, allocator);

    if (dl)
    {
#if PBEX_DL_ALLOCATOR_DOUBLE_LINKED
        PBEX_ATOMIC_BEGIN();

        dl_node_t* node = &CONTAINER_OF(ptr, dl_node_t, data);

        node->prev->next = node->next;
        node->next->prev = node->prev;

        PBEX_ATOMIC_END();

        free(node);
#else
        PBEX_ATOMIC_BEGIN();

        dl_node_t* prev_node = ((dl_node_t*)&dl->head);
        dl_node_t* node      = ((dl_node_t*)&dl->head)->next;
        bool       found     = false;

        while (node != &dl->head)
        {
            if (node->data == ptr)
            {
                prev_node->next = node->next;
                found           = true;
                break;
            }
            else
            {
                prev_node = node;
            }
        }

        PBEX_ATOMIC_END();

        if (found)
        {
            free(node);
        }
#endif
    }
}

pbex_allocator_t pbex_create_heap_allocator(void)
{
    return (pbex_allocator_t) {
        .alloc   = _heap_alloc,
        .dealloc = _heap_dealloc,
    };
}

pbex_pool_allocator_t pbex_create_pool_allocator(uint8_t* ptr, size_t size)
{
    uint8_t* new_ptr = (uint8_t*)ALIGN((uintptr_t)ptr, sizeof(void*));

    size -= new_ptr - ptr;

    return (pbex_pool_allocator_t) {
        .allocator = {.alloc = _pool_alloc, .dealloc = _pool_dealloc},
        .ptr       = new_ptr,
        .size      = size,
    };
}

void pbex_create_dl_allocator(pbex_dl_allocator_t* allocator)
{
    allocator->allocator.alloc   = _dl_alloc;
    allocator->allocator.dealloc = _dl_dealloc;
    allocator->head.next         = &allocator->head;

#if PBEX_DL_ALLOCATOR_DOUBLE_LINKED
    allocator->head.prev = &allocator->head;
#endif
}

void pbex_delete_dl_allocator(pbex_dl_allocator_t* allocator)
{
    pbex_dispose_dl_allocator(allocator);
}

void pbex_dispose_dl_allocator(pbex_dl_allocator_t* allocator)
{
    dl_node_t* head = ((dl_node_t*)&allocator->head);
    dl_node_t* node = head->next;

    while (node != head)
    {
        dl_node_t* next_node = node->next;
        free(node);
        node = next_node;
    }

    allocator->head.next = head;
#if PBEX_DL_ALLOCATOR_DOUBLE_LINKED
    allocator->head.prev = head;
#endif
}
