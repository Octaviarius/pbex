#include "pbex_test.pb.h"

#include <assert.h>
#include <pbex.h>
#include <stdio.h>

#define TEST_EQUAL(a, b)                                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((a) != (b))                                                                                                \
        {                                                                                                              \
            printf(STRINGIFY(__LINE__) ": " STRINGIFY(a) " not equal " STRINGIFY(b) "\r\n");                           \
            exit(1);                                                                                                   \
        }                                                                                                              \
    } while (0)

#define __STRINGIFY(x) #x
#define STRINGIFY(x)   __STRINGIFY(x)

static void _alloc_heap_test(void);
static void _alloc_pool_test(void);
static void _alloc_dl_test(void);

static void _all_test(pbex_allocator_t* allocator);

static void _test1(pbex_allocator_t* allocator);
static void _test2(pbex_allocator_t* allocator);
static void _test3(pbex_allocator_t* allocator);
static void _test4(pbex_allocator_t* allocator);

static void _test1_encode(pb_ostream_t* stream, pbex_allocator_t* allocator);
static void _test1_decode(pb_istream_t* stream, pbex_allocator_t* allocator);

static void _test2_encode(pb_ostream_t* stream, pbex_allocator_t* allocator);
static void _test2_decode(pb_istream_t* stream, pbex_allocator_t* allocator);

static void _test3_encode(pb_ostream_t* stream, pbex_allocator_t* allocator);
static void _test3_decode(pb_istream_t* stream, pbex_allocator_t* allocator);

static void _test4_encode(pb_ostream_t* stream, pbex_allocator_t* allocator);
static void _test4_decode(pb_istream_t* stream, pbex_allocator_t* allocator);

int main(int argc, const char** argv)
{
    _alloc_heap_test();
    _alloc_pool_test();
    _alloc_dl_test();
}

static void _alloc_heap_test(void)
{
    pbex_allocator_t alloc = pbex_create_heap_allocator();

    _all_test(&alloc);
}

static void _alloc_pool_test(void)
{
    uint8_t poolbuf[2048];

    pbex_pool_allocator_t alloc;

    // normal allocation
    alloc = pbex_create_pool_allocator(poolbuf, sizeof(poolbuf));
    _all_test(&alloc.allocator);

    // poor allocation
    alloc = pbex_create_pool_allocator(poolbuf, 64);
    _all_test(&alloc.allocator);
}

static void _alloc_dl_test(void)
{
}

static void _all_test(pbex_allocator_t* allocator)
{
    _test1(allocator);
    _test2(allocator);
    _test3(allocator);
    _test4(allocator);
}

static void _test1(pbex_allocator_t* allocator)
{
    uint8_t obuf[1024];

    pb_ostream_t ostream = pb_ostream_from_buffer(obuf, sizeof(obuf));
    pbex_Test1   out     = pbex_Test1_init_default;
    out.boolean          = true;
    out.integral         = 123;

    TEST_EQUAL(pbex_encode(&ostream, pbex_Test1_fields, &out), true);

    pb_istream_t istream = pb_istream_from_buffer(obuf, ostream.bytes_written);
    pbex_Test1   in      = pbex_Test1_init_default;
    TEST_EQUAL(pbex_decode(allocator, &istream, pbex_Test1_fields, &in), true);

    TEST_EQUAL(out.boolean, in.boolean);
    TEST_EQUAL(out.integral, in.integral);
}

static void _test2(pbex_allocator_t* allocator)
{
    uint8_t obuf[1024];

    pb_ostream_t ostream = pb_ostream_from_buffer(obuf, sizeof(obuf));
    pbex_Test2   out     = pbex_Test2_init_default;
    out.boolean          = true;
    out.integral         = 123;

    static const uint8_t bytes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    static const char    chars[] = "Surprise, motherfucker!";

    out.byteArray = pbex_alloc_bytes(allocator, bytes, sizeof(bytes) / sizeof(bytes[0]));
    out.string    = pbex_alloc_string(allocator, chars, -1);

    TEST_EQUAL(pbex_encode(&ostream, pbex_Test2_fields, &out), true);

    pb_istream_t istream = pb_istream_from_buffer(obuf, ostream.bytes_written);
    pbex_Test2   in      = pbex_Test2_init_default;
    TEST_EQUAL(pbex_decode(allocator, &istream, pbex_Test2_fields, &in), true);

    TEST_EQUAL(out.boolean, in.boolean);
    TEST_EQUAL(out.integral, in.integral);
    TEST_EQUAL(strcmp(pbex_get_cstring(out.string), chars), 0);
    TEST_EQUAL(memcmp(pbex_get_bytes(out.byteArray)->data, bytes, 10), 0);
}

static void _test3(pbex_allocator_t* allocator)
{
}

static void _test4(pbex_allocator_t* allocator)
{
}

static void _test1_encode(pb_ostream_t* stream, pbex_allocator_t* allocator)
{
}
static void _test1_decode(pb_istream_t* stream, pbex_allocator_t* allocator)
{
}

static void _test2_encode(pb_ostream_t* stream, pbex_allocator_t* allocator)
{
}
static void _test2_decode(pb_istream_t* stream, pbex_allocator_t* allocator)
{
}

static void _test3_encode(pb_ostream_t* stream, pbex_allocator_t* allocator)
{
}
static void _test3_decode(pb_istream_t* stream, pbex_allocator_t* allocator)
{
}

static void _test4_encode(pb_ostream_t* stream, pbex_allocator_t* allocator)
{
}
static void _test4_decode(pb_istream_t* stream, pbex_allocator_t* allocator)
{
}
