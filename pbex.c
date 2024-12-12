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

#ifndef PBEX_MALLOC
#define PBEX_MALLOC(size) malloc(size)
#endif

#ifndef PBEX_FREE
#define PBEX_FREE(ptr) free(ptr)
#endif

/**
 * \addtogroup Internal
 * \{
 */

#define OFFSET_OF(type, member)         ((size_t)(uintptr_t) & ((type*)0)->member)
#define CONTAINER_OF(ptr, type, member) (*(type*)((char*)(ptr)-OFFSET_OF(type, member)))

#define ALIGN(val, size)                (((val) + (size)-1) & ~((size)-1))

typedef struct
{
    size_t size;   //!< Size of block chunk (including null symbol)
    char   data[]; //!< Null-terminated string
} pbex_string_holder_t;

typedef struct
{
    size_t  size;   //!< Size of data
    uint8_t data[]; //!< Raw data
} pbex_bytes_holder_t;

/** Internal representation of list node */
struct pbex_list_node
{
    pbex_list_node_t* next;   //!< Pointer to next node
    uint8_t           data[]; //!< Payload
};

/** Encode string callback when \ref pbex_string_alloc is used */
static bool _encode_string(pb_ostream_t* stream, const pb_field_t* field, void* const* arg);
/** Encode string callback when \ref pbex_string_set is used */
static bool _encode_string_static(pb_ostream_t* stream, const pb_field_t* field, void* const* arg);
/** Encode string callback when \ref pbex_bytes_alloc is used */
static bool _encode_bytes(pb_ostream_t* stream, const pb_field_t* field, void* const* arg);
/** Encode bytes callback when \ref pbex_bytes_set is used */
static bool _encode_bytes_static(pb_ostream_t* stream, const pb_field_t* field, void* const* arg);
/** Encode list callback when \ref pbex_list_alloc is used */
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
/** Count list items */
static size_t _list_count(const pbex_list_t* list);
/** Count list items */
static void _list_add_node(pbex_list_t* list, pbex_list_node_t* node);

/**
 * \}
 */

static bool _encode_string(pb_ostream_t* stream, const pb_field_t* field, void* const* arg)
{
    const pbex_string_holder_t* d = (const pbex_string_holder_t*)(*arg);

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
    const pbex_bytes_holder_t* d = (const pbex_bytes_holder_t*)(*arg);

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

static bool _encode_list(pb_ostream_t* stream, const pb_field_t* field, void* const* arg)
{
    const pbex_list_t* d = (const pbex_list_t*)(*arg);

    bool ret = true;

    if (d)
    {
        pbex_list_node_t* node;

        if (PB_LTYPE(field->type) <= PB_LTYPE_LAST_PACKABLE)
        {
            size_t       size = 0;
            pb_ostream_t substream;

            // calc size of elements
            switch (PB_LTYPE(field->type))
            {
                case PB_LTYPE_VARINT:
                case PB_LTYPE_UVARINT:
                {
                    substream = (pb_ostream_t)PB_OSTREAM_SIZING;
                    for (node = d->head; node != NULL; node = node->next)
                    {
                        pb_encode_varint(&substream, *(const uint64_t*)node->data);
                    }
                    size = substream.bytes_written;
                    break;
                }

                case PB_LTYPE_SVARINT:
                {
                    substream = (pb_ostream_t)PB_OSTREAM_SIZING;
                    for (node = d->head; node != NULL; node = node->next)
                    {
                        pb_encode_svarint(&substream, *(const int64_t*)node->data);
                    }
                    size = substream.bytes_written;
                    break;
                }

                case PB_LTYPE_BOOL:
                {
                    size = _list_count(d) * 1;
                    break;
                }

                case PB_LTYPE_FIXED32:
                {
                    size = _list_count(d) * 4;
                    break;
                }

                case PB_LTYPE_FIXED64:
                {
                    size = _list_count(d) * 8;
                    break;
                }
            }

            ret = pb_encode_tag(stream, PB_WT_STRING, field->tag);
            ret = ret && pb_encode_varint(stream, size);

            for (node = d->head; ret && node != NULL; node = node->next)
            {
                switch (PB_LTYPE(field->type))
                {
                    case PB_LTYPE_BOOL:
                        ret = pb_encode_varint(stream, *(const uint64_t*)node->data == 1);
                        break;
                    case PB_LTYPE_VARINT:
                    case PB_LTYPE_UVARINT:
                        ret = pb_encode_varint(stream, *(const uint64_t*)node->data);
                        break;
                    case PB_LTYPE_SVARINT:
                        ret = pb_encode_svarint(stream, *(const int64_t*)node->data);
                        break;
                    case PB_LTYPE_FIXED32:
                        ret = pb_encode_fixed32(stream, (const void*)node->data);
                        break;
                    case PB_LTYPE_FIXED64:
                        ret = pb_encode_fixed64(stream, (const void*)node->data);
                        break;
                }
            }
        }
        else
        {
            for (node = d->head; ret && node != NULL; node = node->next)
            {
                ret = pb_encode_tag_for_field(stream, field);

                if (PB_LTYPE_IS_SUBMSG(field->type))
                {
                    ret = ret && pb_encode_submessage(stream, field->submsg_desc, node->data);
                }
                else
                {
                    pbex_string_t str = pbex_string_get(*(pb_callback_t*)node->data);
                    ret               = ret && pb_encode_string(stream, (pb_byte_t*)str.data, str.size - 1);
                }
            }
        }
    }

    return ret;
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

    pbex_string_holder_t** dd = (pbex_string_holder_t**)arg;
    *dd = (pbex_string_holder_t*)allocator->alloc(allocator, sizeof(pbex_string_holder_t) + stream->bytes_left + 1);
    if (*dd == NULL)
    {
        return false;
    }

    pbex_string_holder_t* d = *dd;

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

    pbex_bytes_holder_t** dd = (pbex_bytes_holder_t**)arg;
    *dd = (pbex_bytes_holder_t*)allocator->alloc(allocator, sizeof(pbex_bytes_holder_t) + stream->bytes_left);
    if (*dd == NULL)
    {
        return false;
    }

    pbex_bytes_holder_t* d = *dd;

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
    bool ret = false;

    pbex_list_t* list = (pbex_list_t*)(*arg);

    if (list)
    {
        pbex_list_node_t* node;
        pb_callback_t*    callback;

        node = list->allocator->alloc(list->allocator, sizeof(pbex_list_node_t) + list->item_size);

        if (node)
        {
            _list_add_node(list, node);

            switch (PB_LTYPE(field->type))
            {
                case PB_LTYPE_BOOL:
                {
                    ret = pb_decode_bool(stream, (bool*)node->data);
                    break;
                }

                case PB_LTYPE_VARINT:
                case PB_LTYPE_UVARINT:
                {
                    ret = pb_decode_varint(stream, (uint64_t*)node->data);
                    break;
                }

                case PB_LTYPE_SVARINT:
                {
                    ret = pb_decode_svarint(stream, (int64_t*)node->data);
                    break;
                }

                case PB_LTYPE_FIXED64:
                {
                    ret = pb_decode_fixed64(stream, node->data);
                    break;
                }

                case PB_LTYPE_FIXED32:
                {
                    ret = pb_decode_fixed32(stream, node->data);
                    break;
                }

                case PB_LTYPE_BYTES:
                {
                    callback                   = (pb_callback_t*)node->data;
                    pbex_bytes_holder_t* bytes = (pbex_bytes_holder_t*)list->allocator
                                                     ->alloc(list->allocator,
                                                             stream->bytes_left + sizeof(pbex_bytes_holder_t));

                    bytes->size = stream->bytes_left;
                    pb_read(stream, bytes->data, stream->bytes_left);
                    callback->arg          = bytes;
                    callback->funcs.decode = _decode_bytes;
                    ret                    = true;
                    break;
                }

                case PB_LTYPE_STRING:
                {
                    callback                  = (pb_callback_t*)node->data;
                    pbex_string_holder_t* str = (pbex_string_holder_t*)list->allocator
                                                    ->alloc(list->allocator,
                                                            stream->bytes_left + 1 + sizeof(pbex_string_holder_t));

                    str->size = stream->bytes_left + 1;
                    pb_read(stream, (uint8_t*)str->data, stream->bytes_left);
                    str->data[str->size - 1] = '\0';
                    callback->arg            = str;
                    callback->funcs.decode   = _decode_string;
                    ret                      = true;
                    break;
                }

                case PB_LTYPE_SUBMESSAGE:
                case PB_LTYPE_SUBMSG_W_CB:
                {
                    ret = _prepare_decode(list->allocator, stream, field->submsg_desc, &node->data);
                    ret = ret && pb_decode(stream, field->submsg_desc, &node->data);
                    break;
                }
            }
        }
    }

    return ret;
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
    bool ret = true;

    pb_field_iter_t it;
    pb_field_iter_begin(&it, descr, inst);

    do
    {
        pb_callback_t* callback;

        switch (PB_HTYPE(it.type))
        {
            case PB_HTYPE_REQUIRED:
            case PB_HTYPE_SINGULAR:
            {
                switch (PB_LTYPE(it.type))
                {
                    case PB_LTYPE_STRING:
                    {
                        callback               = (pb_callback_t*)it.pData;
                        callback->funcs.decode = &_decode_string;
                        callback->arg          = allocator;
                        break;
                    }

                    case PB_LTYPE_BYTES:
                    {
                        callback               = (pb_callback_t*)it.pData;
                        callback->funcs.decode = &_decode_bytes;
                        callback->arg          = allocator;
                        break;
                    }

                    case PB_LTYPE_SUBMESSAGE:
                    {
                        ret = _prepare_decode(allocator, stream, it.submsg_desc, it.pData);
                        break;
                    }
                }
                break;
            }

            case PB_HTYPE_REPEATED:
            {
                callback = (pb_callback_t*)it.pData;

                if (!callback->arg)
                {
                    pbex_list_t* list = (pbex_list_t*)allocator->alloc(allocator, sizeof(pbex_list_t));
                    list->allocator   = allocator;

                    list->head = NULL;
                    list->tail = NULL;

                    callback->funcs.decode = &_decode_repeated;
                    callback->arg          = list;

                    if (!list)
                    {
                        ret = false;
                    }
                    else
                    {
                        switch (PB_LTYPE(it.type))
                        {
                            case PB_LTYPE_BOOL:
                            {
                                list->item_size = 1;
                                break;
                            }

                            case PB_LTYPE_VARINT:
                            case PB_LTYPE_UVARINT:
                            case PB_LTYPE_SVARINT:
                            case PB_LTYPE_FIXED64:
                            {
                                list->item_size = 8;
                                break;
                            }

                            case PB_LTYPE_FIXED32:
                            {
                                list->item_size = 4;
                                break;
                            }

                            case PB_LTYPE_BYTES:
                            case PB_LTYPE_STRING:
                            {
                                list->item_size = sizeof(pb_callback_t);
                                break;
                            }

                            case PB_LTYPE_SUBMSG_W_CB:
                            case PB_LTYPE_SUBMESSAGE:
                            {
                                list->item_size = _prepare_size_of_struct(it.submsg_desc);

                                break;
                            }
                        }
                    }
                }

                break;
            }

            case PB_HTYPE_ONEOF:
            {
                switch (PB_LTYPE(it.type))
                {
                    case PB_LTYPE_SUBMSG_W_CB:
                    case PB_LTYPE_SUBMESSAGE:
                        callback = (pb_callback_t*)it.pSize - 1;
                        if (!callback->arg)
                        {
                            callback->funcs.decode = &_decode_oneof;
                            callback->arg          = allocator;
                        }
                        break;
                }
                break;
            }
        }

    } while (ret && pb_field_iter_next(&it));

    return ret;
}

static size_t _list_count(const pbex_list_t* list)
{
    size_t count = 0;
    for (pbex_list_node_t* node = list->head; node != NULL; node = node->next)
    {
        count++;
    }
    return count;
}

static void _list_add_node(pbex_list_t* list, pbex_list_node_t* node)
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
    return (pb_ostream_t)PB_OSTREAM_SIZING;
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

        void* ptr = PBEX_MALLOC(*size);

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
                PBEX_FREE(ptr);
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

        switch (PB_HTYPE(it.type))
        {
            case PB_HTYPE_REQUIRED:
            case PB_HTYPE_SINGULAR:
            {
                switch (PB_LTYPE(it.type))
                {
                    case PB_LTYPE_BYTES:
                    {
                        callback = (pb_callback_t*)it.pData;
                        if (callback->funcs.encode != _encode_bytes && callback->funcs.decode != _decode_bytes)
                        {
                            callback = NULL;
                        }
                        break;
                    }

                    case PB_LTYPE_STRING:
                    {
                        callback = (pb_callback_t*)it.pData;
                        if (callback->funcs.encode != _encode_string && callback->funcs.decode != _decode_string)
                        {
                            callback = NULL;
                        }
                        break;
                    }
                }
                break;
            }

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
                            switch (PB_LTYPE(it.type))
                            {
                                case PB_LTYPE_BYTES:
                                {
                                    pb_callback_t* sub_callback = (pb_callback_t*)node->data;

                                    if (sub_callback->funcs.encode == _encode_bytes
                                        || sub_callback->funcs.decode == _decode_bytes)
                                    {
                                        list->allocator->dealloc(list->allocator, sub_callback->arg);
                                    }
                                    break;
                                }

                                case PB_LTYPE_STRING:
                                {
                                    pb_callback_t* sub_callback = (pb_callback_t*)node->data;

                                    if (sub_callback->funcs.encode == _encode_string
                                        || sub_callback->funcs.decode == _decode_string)
                                    {
                                        list->allocator->dealloc(list->allocator, sub_callback->arg);
                                    }
                                    break;
                                }

                                case PB_LTYPE_SUBMSG_W_CB:
                                case PB_LTYPE_SUBMESSAGE:
                                {
                                    pbex_release(list->allocator, it.submsg_desc, &node->data);
                                    break;
                                }
                            }

                            pbex_list_node_t* prev_node = node;
                            node                        = node->next;
                            list->allocator->dealloc(list->allocator, prev_node);
                        }
                    }
                }

                break;
            }

            case PB_HTYPE_ONEOF:
            {
                if (*(pb_size_t*)it.pSize == it.tag)
                {
                    callback      = (pb_callback_t*)it.pSize - 1;
                    callback->arg = NULL;
                    callback      = NULL;
                    pbex_release(allocator, it.submsg_desc, it.pData);
                }
                break;
            }
        }

        if (callback && callback->arg && callback->arg != allocator)
        {
            allocator->dealloc(allocator, callback->arg);
            callback->arg = NULL;
        }

    } while (pb_field_iter_next(&it));

    return true;
}

pb_callback_t pbex_list_alloc(pbex_allocator_t* allocator, size_t item_size)
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
    size_t count;

    PBEX_ATOMIC_BEGIN();
    pbex_list_t* l = (pbex_list_t*)list.arg;

    if (l)
    {
        count = _list_count(l);
    }
    else
    {
        count = 0;
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

pb_callback_t pbex_string_alloc(pbex_allocator_t* allocator, const char* str, size_t len)
{
    if (len == 0)
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

    pbex_string_holder_t* d = (pbex_string_holder_t*)allocator->alloc(allocator,
                                                                      sizeof(pbex_string_holder_t) + len + 1);

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

pb_callback_t pbex_string_set(const pbex_string_t* str)
{
    return (pb_callback_t) {
        .funcs = {.encode = _encode_string_static},
        .arg   = (void*)str,
    };
}

pb_callback_t pbex_cstring_set(const char* str)
{
    return (pb_callback_t) {
        .funcs = {.encode = _encode_cstring_static},
        .arg   = (void*)str,
    };
}

pbex_string_t pbex_string_get(pb_callback_t callback)
{
    pbex_string_t ret;

    if (callback.funcs.encode == _encode_string || callback.funcs.decode == _decode_string)
    {
        ret.size = ((const pbex_string_holder_t*)callback.arg)->size;
        ret.data = ((const pbex_string_holder_t*)callback.arg)->data;
    }
    else if (callback.funcs.encode == _encode_string_static)
    {
        ret = *((const pbex_string_t*)callback.arg);
    }
    else if (callback.funcs.encode == _encode_cstring_static)
    {
        ret.data = ((const char*)callback.arg);
        ret.size = strlen(ret.data) + 1;
    }
    else
    {
        ret.size = 0;
        ret.data = NULL;
    }

    return ret;
}

bool pbex_string_get_p(pb_callback_t callback, const char** str_ptr, size_t* size_ptr)
{
    pbex_string_t str = pbex_string_get(callback);

    if (str.data)
    {
        if (str_ptr)
        {
            *str_ptr = str.data;
        }

        if (size_ptr)
        {
            *size_ptr = str.size;
        }

        return true;
    }

    return false;
}

const char* pbex_cstring_get(pb_callback_t callback)
{
    if (callback.funcs.encode == _encode_cstring_static)
    {
        return (const char*)callback.arg;
    }
    else
    {
        pbex_string_t str = pbex_string_get(callback);
        return str.data;
    }
}

pb_callback_t pbex_bytes_alloc(pbex_allocator_t* allocator, const void* data, size_t count)
{
    pbex_bytes_holder_t* d = (pbex_bytes_holder_t*)allocator->alloc(allocator, sizeof(pbex_bytes_holder_t) + count);

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

pb_callback_t pbex_bytes_set(const pbex_bytes_t* bytes)
{
    return (pb_callback_t) {
        .funcs = {.encode = _encode_bytes_static},
        .arg   = (void*)bytes,
    };
}

pbex_bytes_t pbex_bytes_get(pb_callback_t callback)
{
    pbex_bytes_t ret;

    if (callback.funcs.encode == _encode_bytes || callback.funcs.decode == _decode_bytes)
    {
        ret.size = ((const pbex_bytes_holder_t*)callback.arg)->size;
        ret.data = ((const pbex_bytes_holder_t*)callback.arg)->data;
    }
    else if (callback.funcs.encode == _encode_bytes_static)
    {
        ret = *(const pbex_bytes_t*)callback.arg;
    }
    else
    {
        ret.size = 0;
        ret.data = NULL;
    }

    return ret;
}

bool pbex_bytes_get_p(pb_callback_t callback, const void** data_ptr, size_t* size_ptr)
{
    pbex_bytes_t bytes = pbex_bytes_get(callback);

    if (bytes.data)
    {
        if (data_ptr)
        {
            *data_ptr = bytes.data;
        }

        if (size_ptr)
        {
            *size_ptr = bytes.size;
        }

        return true;
    }

    return false;
}

size_t pbex_bytes_copy_to(pb_callback_t callback, void* data, size_t offset, size_t size)
{
    pbex_bytes_t bytes = pbex_bytes_get(callback);

    if (bytes.data && data && offset < bytes.size)
    {
        if (offset + size > bytes.size)
        {
            size = bytes.size - offset;
        }

        memcpy(data, &bytes.data[offset], size);
        return size;
    }

    return 0;
}

//-----------------------------------------------

static void* _heap_alloc(pbex_allocator_t* self, size_t size)
{
    (void)self;
    return PBEX_MALLOC(size);
}

static void _heap_dealloc(pbex_allocator_t* self, void* ptr)
{
    (void)self;
    PBEX_FREE(ptr);
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
    dl_node_t* prev;
    uint8_t    data[];
};

static void* _dl_alloc(pbex_allocator_t* self, size_t size)
{
    pbex_dl_allocator_t* dl       = &CONTAINER_OF(self, pbex_dl_allocator_t, allocator);
    dl_node_t*           new_node = (dl_node_t*)PBEX_MALLOC(sizeof(dl_node_t) + size);

    if (new_node)
    {
        dl_node_t* head = (dl_node_t*)&dl->head;

        PBEX_ATOMIC_BEGIN();
        head->next->prev = new_node;
        new_node->next   = head->next;
        head->next       = new_node;
        new_node->prev   = head;
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
        PBEX_ATOMIC_BEGIN();

        dl_node_t* node = &CONTAINER_OF(ptr, dl_node_t, data);

        // already detached
        if (node->prev == NULL || node->next == NULL)
        {
            PBEX_ATOMIC_END();
            return;
        }

        node->prev->next = node->next;
        node->next->prev = node->prev;

        // mark detached
        node->next = NULL;
        node->prev = NULL;

        PBEX_ATOMIC_END();

        PBEX_FREE(node);
    }
}

pbex_allocator_t pbex_heap_allocator_create(void)
{
    return (pbex_allocator_t) {
        .alloc   = _heap_alloc,
        .dealloc = _heap_dealloc,
    };
}

pbex_pool_allocator_t pbex_pool_allocator_create(uint8_t* ptr, size_t size)
{
    uint8_t* new_ptr = (uint8_t*)ALIGN((uintptr_t)ptr, sizeof(void*));

    size -= new_ptr - ptr;

    return (pbex_pool_allocator_t) {
        .allocator = {.alloc = _pool_alloc, .dealloc = _pool_dealloc},
        .ptr       = new_ptr,
        .size      = size,
    };
}

size_t pbex_pool_allocator_remain(pbex_pool_allocator_t* allocator)
{
    return allocator->size - allocator->pos;
}

void pbex_pool_allocator_dispose(pbex_pool_allocator_t* allocator)
{
    allocator->pos = 0;
}

void pbex_dl_allocator_create(pbex_dl_allocator_t* allocator)
{
    allocator->allocator.alloc   = _dl_alloc;
    allocator->allocator.dealloc = _dl_dealloc;
    allocator->head.next         = &allocator->head;
    allocator->head.prev         = &allocator->head;
}

void pbex_dl_allocator_delete(pbex_dl_allocator_t* allocator)
{
    pbex_dl_allocator_dispose(allocator);
}

void pbex_dl_allocator_dispose(pbex_dl_allocator_t* allocator)
{
    // detach from head
    PBEX_ATOMIC_BEGIN();
    dl_node_t fake_head;

    dl_node_t* head = ((dl_node_t*)&allocator->head);

    fake_head.next       = head->next;
    fake_head.prev       = head->prev;
    head->next->prev     = &fake_head;
    head->prev->next     = &fake_head;
    allocator->head.next = head;
    allocator->head.prev = head;

    head = &fake_head;

    dl_node_t* next_node;

    for (dl_node_t* node = head->next; node != head; node = next_node)
    {
        next_node = node->next;

        // already detached
        if (node->prev == NULL || node->next == NULL)
        {
            continue;
        }

        node->prev->next = node->next;
        node->next->prev = node->prev;

        // mark detached
        node->next = NULL;
        node->prev = NULL;

        PBEX_ATOMIC_END();
        PBEX_FREE(node);
        PBEX_ATOMIC_BEGIN();
    }

    PBEX_ATOMIC_END();
}

size_t pbex_dl_allocator_count(pbex_dl_allocator_t* allocator)
{
    size_t count = 0;

    PBEX_ATOMIC_BEGIN();
    for (dl_node_t* node = (dl_node_t*)allocator->head.next; node != (dl_node_t*)&allocator->head; node = node->next)
    {
        count++;
    }
    PBEX_ATOMIC_END();

    return count;
}
