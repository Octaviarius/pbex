#ifndef PBEX_H
#define PBEX_H

#include "pb.h"
#include "pb_common.h"
#include "pb_decode.h"
#include "pb_encode.h"

#include <stdlib.h>
#include <sys/types.h>

// #define PBEX_ATOMIC_BEGIN()
// #define PBEX_ATOMIC_END()
// #define PBEX_DL_ALLOCATOR_DOUBLE_LINKED 0
// #define PBEX_EXTERNAL_INCLUDE "pbex_port.h"

/*
 * PBEX - lightweight and comfortable way to utilize nanoPB library
 */

#ifdef __cplusplus
extern "C"
{
#endif

//--------------------------------------------

typedef struct pbex_allocator pbex_allocator_t;

struct pbex_allocator
{
    void* (*alloc)(pbex_allocator_t* self, size_t size);
    void (*dealloc)(pbex_allocator_t* self, void* ptr);
};

pbex_allocator_t pbex_create_heap_allocator(void);

typedef struct
{
    pbex_allocator_t allocator;

    uint8_t* ptr;
    size_t   size;
    size_t   pos;
} pbex_pool_allocator_t;

pbex_pool_allocator_t pbex_create_pool_allocator(uint8_t* ptr, size_t size);

typedef struct
{
    pbex_allocator_t allocator;

    struct
    {
        void* next;
#if PBEX_DL_ALLOCATOR_DOUBLE_LINKED
        void* prev;
#endif
    } head;
} pbex_dl_allocator_t;

void pbex_create_dl_allocator(pbex_dl_allocator_t* allocator);
void pbex_delete_dl_allocator(pbex_dl_allocator_t* allocator);
void pbex_dispose_dl_allocator(pbex_dl_allocator_t* allocator);

//--------------------------------------------

typedef struct
{
    size_t size;
    char   data[];
} pbex_string_t;

typedef struct
{
    size_t    size;
    pb_byte_t data[];
} pbex_bytes_t;

typedef struct pbex_list_node pbex_list_node_t;
typedef struct
{
    pbex_allocator_t* allocator;
    size_t            item_size;
    pbex_list_node_t* head;
    pbex_list_node_t* tail;
} pbex_list_t;

/**
 * \brief Empty buffer. Usefull to encount total bytes for encoding
 *
 *
 * \return pb_ostream_t
 */
pb_ostream_t pbex_create_ostream_stub(void);

/**
 * \brief Serialize structure to buffer
 *
 * \param stream
 * \param descr
 * \param inst
 *
 */
bool pbex_encode(pb_ostream_t* stream, const pb_msgdesc_t* descr, const void* inst);

/**
 * \brief Deserialize stream to structure. It uses allocator to auto allocate data during decoding
 *
 * \param allocator
 * \param stream
 * \param descr
 * \param inst
 *
 */
bool pbex_decode(pbex_allocator_t* allocator, pb_istream_t* stream, const pb_msgdesc_t* descr, void* inst);

/**
 * \brief Wrapper for pbex_encode, just uses buffer pointer
 *
 * \param descr
 * \param inst
 * \param buffer
 * \param size
 *
 */
bool pbex_encode_to_buffer(const pb_msgdesc_t* descr, const void* inst, void* buffer, size_t* size);

/**
 * \brief Wrapper for pbex_encode. Allocate a buffer with necessary size.
 *
 * \param descr
 * \param inst
 * \param buffer Pointer to buffer variable
 * \param size Pointer to store size of allocated data
 *
 */
bool pbex_encode_to_dynbuffer(const pb_msgdesc_t* descr, const void* inst, void** buffer, size_t* size);

/**
 * \brief Wrapper for pbex_decode, just uses buffer fo deserialization
 *
 * \param allocator
 * \param descr
 * \param inst
 * \param buffer
 * \param size
 */
bool pbex_decode_from_buffer(pbex_allocator_t*   allocator,
                             const pb_msgdesc_t* descr,
                             void*               inst,
                             const void*         buffer,
                             size_t              size);
/**
 * \brief Releases all allocated memory. Especially it must be used if your allocator
 * don't account allocated memory and can't deallocate memory in explicit way (eg heap_allocator)
 *
 * \param allocator
 * \param descr
 * \param inst
 *
 * \note It should be used after succeed calling pbex_decode
 */
bool pbex_release(pbex_allocator_t* allocator, const pb_msgdesc_t* descr, void* inst);

/**
 * \brief Allocate string for encoding
 *
 * \param allocator
 * \param str
 * \param len
 *
 * \return pb_callback_t
 */
pb_callback_t pbex_alloc_string(pbex_allocator_t* allocator, const char* str, ssize_t len);

/**
 * \brief Allocate list
 *
 * \param allocator
 * \param item_size
 *
 * \return pb_callback_t
 */
pb_callback_t pbex_alloc_list(pbex_allocator_t* allocator, size_t item_size);

/**
 * \brief Encount list nodes
 *
 * \param callback
 *
 * \return size_t
 */
size_t pbex_list_count(pb_callback_t callback);

/**
 * \brief Add new node
 *
 * \param callback
 *
 * \return Pointer to created node
 */
void* pbex_list_add_node(pb_callback_t callback);

/**
 * \brief Get i-node
 *
 * \param callback
 * \param idx
 *
 * \return Pointer to returned node. NULL if no node is available
 */
void* pbex_list_get_node(pb_callback_t callback, size_t idx);

/**
 * \brief Get the nest node
 *
 * \return Pointer to returned node. NULL if no node is available
 */
void* pbex_list_next_node(const void* node);

/**
 * \brief Set string for encoding.
 *
 * \param str
 *
 * \return pb_callback_t
 *
 * \note It doesn't allocate memory, just set encoder function and pointer to your structure.
 * Make sure your structure exists while nano pb is encoding a structure
 */
pb_callback_t pbex_set_string(const pbex_string_t* str);

/**
 * \brief Allocate bytes for encoding
 *
 * \param allocator
 * \param data
 * \param count
 *
 * \return pb_callback_t
 *
 * \note It doesn't allocate memory, just set encoder function and pointer to your structure.
 * Make sure your structure exists while nano pb is encoding a structure
 */
pb_callback_t pbex_alloc_bytes(pbex_allocator_t* allocator, const void* data, size_t count);

/**
 * \brief Set bytes for encoding
 *
 * \param bytes
 *
 * \return pb_callback_t
 */
pb_callback_t pbex_set_bytes(const pbex_bytes_t* bytes);

/**
 * \brief Get bytes structure
 *
 * \param callback
 *
 * \return const pbex_bytes_t*
 */
const pbex_bytes_t* pbex_get_bytes(pb_callback_t callback);

/**
 * \brief Get string structure
 *
 * \param callback
 *
 * \return const pbex_string_t*
 */
const pbex_string_t* pbex_get_string(pb_callback_t callback);

/**
 * \brief Get C-string. It gets pbex_string_t and return only pointer to data field
 *
 * \param callback
 *
 * \return const char*
 */
const char* pbex_get_cstring(pb_callback_t callback);

#ifdef __cplusplus
}
#endif

#endif // PBEX_H
