#ifndef PBEX_H
#define PBEX_H

#include "pb.h"
#include "pb_common.h"
#include "pb_decode.h"
#include "pb_encode.h"

#include <stdint.h>
#include <stdlib.h>

#if SIZE_MAX == UINT8_MAX
typedef int8_t ssize_t;
#elif SIZE_MAX == UINT16_MAX
typedef int16_t ssize_t;
#elif SIZE_MAX == UINT32_MAX
typedef int32_t ssize_t;
#elif SIZE_MAX == UINT64_MAX
typedef int64_t ssize_t;
#elif SIZE_MAX == UINT128_MAX
typedef int128_t ssize_t;
#else
#error "Can't define ssize_t"
#endif

#define PBEX_VERSION_MAJOR 2
#define PBEX_VERSION_MINOR 0
#define PBEX_VERSION_PATCH 0

/**
 * \defgroup mainMacros Main macros
 * All main macros that are used in library
 */

/**
 * \defgroup allocators Allocators
 * Allocators are one of the central features of pbex.
 * You can flexible manipulate memory.
 * \{
 * \defgroup allocatorsTypes Allocators types
 * \defgroup allocatorsApi Allocators API
 * \}
 */

/**
 * \defgroup main Main
 * Main API and types of pbex
 * \{
 * \defgroup mainTypes Main types
 * \defgroup mainApi Main API
 * \}
 */

/**
 * \ingroup mainMacros
 * \{
 *
 * \def PBEX_ATOMIC_BEGIN()
 * Using for sharing instances in several tasks or interrupts. It protects
 * against race conditions.
 *
 * \def PBEX_ATOMIC_END() PBEX_ATOMIC_BEGIN()
 * Using for sharing instances in several tasks or interrupts. It protects
 * against race conditions.
 *
 * \def PBEX_EXTERNAL_INCLUDE
 * Includes defined file in pbex.c to provide PBEX_ATOMIC_x macros functionality
 *
 * \def PBEX_MALLOC(size)
 * malloc function definition
 *
 * \def PBEX_FREE(ptr)
 * free function definition
 *
 * \}
 */

/*
 * PBEX - lightweight and comfortable way to utilize nanoPB library
 */

#ifdef __cplusplus
extern "C"
{
#endif

/** \ingroup allocatorsTypes */
typedef struct pbex_allocator pbex_allocator_t;
/** \ingroup allocatorsTypes */
typedef void* (*pbex_allocator_alloc_t)(pbex_allocator_t* self, size_t size); //!< Allocation function type
/** \ingroup allocatorsTypes */
typedef void (*pbex_allocator_dealoc_t)(pbex_allocator_t* self, void* ptr); //!< Deallocation function type

/**
 * \ingroup allocatorsTypes
 * \brief Basic abstraction for allocation and deallocation
 */
struct pbex_allocator
{
    pbex_allocator_alloc_t  alloc;   //!< Allocation method
    pbex_allocator_dealoc_t dealloc; //!< Deallocation method
};

/**
 * \ingroup allocatorsApi
 * \brief Creates heap allocator
 *
 * \return pbex_allocator_t
 *
 * \note This allocator doesn't store any info about allocated instances, so
 * you must call \ref pbex_release to release allocated data.
 */
pbex_allocator_t pbex_heap_allocator_create(void);

/**
 * \ingroup allocatorsTypes
 * \brief Pool allocator.
 * It strict sequentially allocates data in linear buffer.
 *
 * \note THis allocator can't deallocate memory, so you must control linear buffer.
 * Usually it's statically allocated chunk of memory, or on-stack, but if the chunk
 * is made using \ref malloc() - you must call \ref free().
 */
typedef struct
{
    pbex_allocator_t allocator; //!< \ref pbex_allocator_t

    uint8_t* ptr;  //!< Pointer to linear buffer (must be aligned by the machine word)
    size_t   size; //!< Size of linear buffer
    size_t   pos;  //!< Current position for next allocation
} pbex_pool_allocator_t;

/**
 * \ingroup allocatorsApi
 * \brief Creates pool allocator
 *
 * \param ptr //!< Pointer to linear buffer
 * \param size //!< Size of the buffer
 *
 * \return pbex_pool_allocator_t
 */
pbex_pool_allocator_t pbex_pool_allocator_create(uint8_t* ptr, size_t size);

/**
 * \ingroup allocatorsApi
 * \brief Get free memory
 *
 * \param allocator
 *
 * \return size_t
 */
size_t pbex_pool_allocator_remain(pbex_pool_allocator_t* allocator);

/**
 * \ingroup allocatorsApi
 * \brief Dispose pool allocator
 *
 * \param allocator
 *
 * \return size_t
 */
void pbex_pool_allocator_dispose(pbex_pool_allocator_t* allocator);

/**
 * \ingroup allocatorsTypes
 * \brief Disposable list allocator
 * It can fully control memory allocation and deallocation.
 * When you allocate some memory instances you can free them via
 * explicit call \ref  pbex_dl_allocator_dispose or \ref pbex_dl_allocator_delete,
 * or via \ref pbex_release.
 *
 * \note It uses malloc() and free() functions.
 */
typedef struct
{
    pbex_allocator_t allocator; //!< \ref pbex_allocator_t

    struct
    {
        void* next; //!< Pointer to next node
        void* prev; //!< Pointer to previous node
    } head;         //!< stores the first node, which hasn't got any data, but node header.
} pbex_dl_allocator_t;

/**
 * \ingroup allocatorsApi
 * \brief Creates (constructs) DL allocator
 *
 * \param allocator
 */
void pbex_dl_allocator_create(pbex_dl_allocator_t* allocator);

/**
 * \ingroup allocatorsApi
 * \brief Delete allocator and free all allocated blocks.
 *
 * \param allocator
 */
void pbex_dl_allocator_delete(pbex_dl_allocator_t* allocator);

/**
 * \ingroup allocatorsApi
 * \brief Dispose the allocator. The same as \ref pbex_dl_allocator_delete
 *
 * \param allocator
 */
void pbex_dl_allocator_dispose(pbex_dl_allocator_t* allocator);

/**
 * \ingroup allocatorsApi
 * \brief Encount allocated items
 *
 * \param allocator
 */
size_t pbex_dl_allocator_count(pbex_dl_allocator_t* allocator);

/**
 * \}
 */

/**
 * \ingroup mainTypes
 * \{
 */

/**
 * \brief Full-string data type.
 * It stores string data
 */
typedef struct
{
    size_t size;   //!< Size of block chunk (including null symbol)
    char   data[]; //!< Null-terminated string
} pbex_string_t;

/**
 * \brief Raw bytes data type.
 * It stores raw data.
 */
typedef struct
{
    size_t  size;   //!< Size of data
    uint8_t data[]; //!< Raw data
} pbex_bytes_t;

/**
 * \brief List data type
 * It stores data for repeated fields. List was selected instead of array
 * because it's the most efficient container to allocate unknown numerous of instances
 * without reallocations, although it consumes a bit more memory per instance (by sizeof(void*)).
 */
typedef struct pbex_list_node pbex_list_node_t;
typedef struct
{
    pbex_allocator_t* allocator; //!< Pointer to allocator for future allocating
    size_t            item_size; //!< Item size
    pbex_list_node_t* head;      //!< Pointer to the first node
    pbex_list_node_t* tail;      //!< Pointer to the last node
} pbex_list_t;

/**
 * \}
 */

/**
 * \addtogroup mainApi
 * \{
 */

/**
 * \brief Empty buffer. Usefull to encount total bytes for encoding
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
 * \brief Allocate list
 *
 * \param allocator
 * \param item_size
 *
 * \return pb_callback_t
 */
pb_callback_t pbex_list_alloc(pbex_allocator_t* allocator, size_t item_size);

/**
 * \brief Encount list nodes
 *
 * \param list
 *
 * \return size_t
 */
size_t pbex_list_count(pb_callback_t list);

/**
 * \brief Add new node
 *
 * \param list
 *
 * \return Pointer to created node
 */
void* pbex_list_add_node(pb_callback_t list);

/**
 * \brief Add new node after
 *
 * \param list
 * \param node
 *
 * \return Pointer to created node
 */
void* pbex_list_add_node_after(pb_callback_t list, const void* node);

/**
 * \brief Get i-node
 *
 * \param list
 * \param idx
 *
 * \return Pointer to returned node. NULL if no node is available
 */
void* pbex_list_get_node(pb_callback_t list, size_t idx);

/**
 * \brief Get the nest node
 *
 * \return Pointer to returned node. NULL if no node is available
 */
void* pbex_list_next_node(const void* node);

/**
 * \brief Allocate string for encoding
 *
 * \param allocator
 * \param str
 * \param len
 *
 * \return pb_callback_t
 */
pb_callback_t pbex_string_alloc(pbex_allocator_t* allocator, const char* str, ssize_t len);

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
pb_callback_t pbex_string_set(const pbex_string_t* str);

/**
 * \brief Set C-string
 *
 * \param str
 *
 * \return pb_callback_t
 */
pb_callback_t pbex_cstring_set(const char* str);

/**
 * \brief Get string structure
 *
 * \param callback
 *
 * \return const pbex_string_t*
 */
const pbex_string_t* pbex_string_get(pb_callback_t callback);

/**
 * \brief Get string data directly to variables. It's a syntax sugar.
 *
 * \param callback
 * \param str_ptr
 * \param size_ptr
 *
 * \return true if it's OK
 */
bool pbex_string_get_p(pb_callback_t callback, const char** str_ptr, size_t* size_ptr);

/**
 * \brief Get C-string. It gets pbex_string_t and return only pointer to data field
 *
 * \param callback
 *
 * \return const char*
 */
const char* pbex_cstring_get(pb_callback_t callback);

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
pb_callback_t pbex_bytes_alloc(pbex_allocator_t* allocator, const void* data, size_t count);

/**
 * \brief Set bytes for encoding
 *
 * \param bytes
 *
 * \return pb_callback_t
 */
pb_callback_t pbex_bytes_set(const pbex_bytes_t* bytes);

/**
 * \brief Get bytes structure
 *
 * \param callback
 *
 * \return const pbex_bytes_t*
 */
const pbex_bytes_t* pbex_bytes_get(pb_callback_t callback);

/**
 * \brief Get bytes data directly to variables. It's a syntax sugar.
 *
 * \param callback
 * \param data_ptr
 * \param size_ptr
 *
 * \return true if it's OK
 */
bool pbex_bytes_get_p(pb_callback_t callback, const void** data_ptr, size_t* size_ptr);

/**
 * \brief Copy bytes directly to variable. It's a syntax sugar.
 *
 * \param callback
 * \param data
 * \param offset
 * \param size
 *
 * \return size_t
 */
size_t pbex_bytes_copy_to(pb_callback_t callback, void* data, size_t offset, size_t size);

/**
 * \}
 */

#ifdef __cplusplus
}
#endif

#endif // PBEX_H
