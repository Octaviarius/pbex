#include "pbex_test.pb.h"

#include <assert.h>
#include <pbex.h>
#include <stdio.h>

#define COUNT_OF(arr) (sizeof(arr) / sizeof(arr[0]))

#define TEST_EQUAL(a, b)                                                                                               \
    do                                                                                                                 \
    {                                                                                                                  \
        if ((a) != (b))                                                                                                \
        {                                                                                                              \
            printf("Line " STRINGIFY(__LINE__) ": " STRINGIFY(a) " not equal " STRINGIFY(b) "\r\n");                   \
            exit(1);                                                                                                   \
        }                                                                                                              \
    } while (0)

#define __STRINGIFY(x) #x
#define STRINGIFY(x)   __STRINGIFY(x)

static void _alloc_heap_test(void);
static void _alloc_pool_test(void);
static void _alloc_dl_test(void);

static void _lack_of_memory_test(void);
static void _all_test(pbex_allocator_t* allocator);

static void _test1(pbex_allocator_t* allocator);
static void _test2(pbex_allocator_t* allocator);
static void _test3(pbex_allocator_t* allocator);
static void _test4(pbex_allocator_t* allocator);
static void _test5(pbex_allocator_t* allocator);
static void _test6(pbex_allocator_t* allocator);
static void _test7(pbex_allocator_t* allocator);
static void _test8(pbex_allocator_t* allocator);

int main(int argc, const char** argv)
{
    _alloc_heap_test();
    _alloc_pool_test();
    _alloc_dl_test();
    _lack_of_memory_test();
}

static void _alloc_heap_test(void)
{
    pbex_allocator_t alloc = pbex_heap_allocator_create();

    _all_test(&alloc);
}

static void _alloc_pool_test(void)
{
    uint8_t poolbuf[2048];

    pbex_pool_allocator_t alloc;

    // normal allocation
    alloc = pbex_pool_allocator_create(poolbuf, sizeof(poolbuf));
    _all_test(&alloc.allocator);
}

static void _alloc_dl_test(void)
{
    pbex_dl_allocator_t dl;
    pbex_dl_allocator_create(&dl);
    _all_test(&dl.allocator);

    TEST_EQUAL(pbex_dl_allocator_count(&dl), 0);
}

typedef struct
{
    pbex_allocator_t allocator;
    size_t           allocs;
    size_t           max_allocs;
} lack_allocator_t;

void* _lack_alloc(pbex_allocator_t* allocator, size_t size)
{
    lack_allocator_t* alloc = (lack_allocator_t*)allocator;
    if (alloc->allocs >= alloc->max_allocs)
    {
        return NULL;
    }
    else
    {
        alloc->allocs++;
        return malloc(size);
    }
}

void _lack_dealloc(pbex_allocator_t* allocator, void* ptr)
{
    lack_allocator_t* alloc = (lack_allocator_t*)allocator;
    alloc->allocs--;
    free(ptr);
}

static void _lack_of_memory_test(void)
{
    lack_allocator_t lack = {
        .allocator  = {.alloc = _lack_alloc, .dealloc = _lack_dealloc},
        .max_allocs = 5,
    };

    uint8_t obuf[1024];

    pbex_allocator_t nonlack = pbex_heap_allocator_create();

    pb_ostream_t ostream = pb_ostream_from_buffer(obuf, sizeof(obuf));
    pbex_Test6   out     = pbex_Test6_init_default;

    out.integrals = pbex_list_alloc(&nonlack, sizeof(int32_t));
    int32_t* it;
    for (int i = 0; i < 10; i++)
    {
        it = pbex_list_add_node(out.integrals);
        if (!it)
        {
            break;
        }

        *it = i;
    }

    TEST_EQUAL(pbex_encode(&ostream, pbex_Test6_fields, &out), true);
    TEST_EQUAL(pbex_release(&nonlack, pbex_Test6_fields, &out), true);

    // failed decoding and emergent release
    pb_istream_t istream = pb_istream_from_buffer(obuf, ostream.bytes_written);
    pbex_Test6   in      = pbex_Test6_init_default;
    TEST_EQUAL(pbex_decode(&lack.allocator, &istream, pbex_Test6_fields, &in), false);

    TEST_EQUAL(pbex_release(&lack.allocator, pbex_Test6_fields, &in), true);

    TEST_EQUAL(lack.allocs, 0);
}

static void _all_test(pbex_allocator_t* allocator)
{
    _test1(allocator);
    _test2(allocator);
    _test3(allocator);
    _test4(allocator);
    _test5(allocator);
    _test6(allocator);
    _test7(allocator);
    _test8(allocator);
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

    // used, but doesn't matter for non allocatable objects
    TEST_EQUAL(pbex_release(allocator, pbex_Test1_fields, &out), true);
    TEST_EQUAL(pbex_release(allocator, pbex_Test1_fields, &in), true);
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

    out.byteArray = pbex_bytes_alloc(allocator, bytes, COUNT_OF(bytes));
    out.string    = pbex_string_alloc(allocator, chars, -1);

    TEST_EQUAL(pbex_encode(&ostream, pbex_Test2_fields, &out), true);

    pb_istream_t istream = pb_istream_from_buffer(obuf, ostream.bytes_written);
    pbex_Test2   in      = pbex_Test2_init_default;
    TEST_EQUAL(pbex_decode(allocator, &istream, pbex_Test2_fields, &in), true);

    TEST_EQUAL(out.boolean, in.boolean);
    TEST_EQUAL(out.integral, in.integral);
    TEST_EQUAL(strcmp(pbex_cstring_get(out.string), pbex_cstring_get(in.string)), 0);
    TEST_EQUAL(memcmp(pbex_bytes_get(out.byteArray)->data, pbex_bytes_get(in.byteArray)->data, 10), 0);

    TEST_EQUAL(pbex_release(allocator, pbex_Test2_fields, &out), true);
    TEST_EQUAL(pbex_release(allocator, pbex_Test2_fields, &in), true);
}

static void _test3(pbex_allocator_t* allocator)
{
    uint8_t obuf[1024];

    // test1 message option
    pb_ostream_t ostream    = pb_ostream_from_buffer(obuf, sizeof(obuf));
    pbex_Test3   out        = pbex_Test3_init_default;
    out.which_body          = pbex_Test3_item1_tag;
    out.body.item1.boolean  = true;
    out.body.item1.integral = 666;

    TEST_EQUAL(pbex_encode(&ostream, pbex_Test3_fields, &out), true);

    pb_istream_t istream = pb_istream_from_buffer(obuf, ostream.bytes_written);
    pbex_Test3   in      = pbex_Test3_init_default;
    TEST_EQUAL(pbex_decode(allocator, &istream, pbex_Test3_fields, &in), true);

    TEST_EQUAL(out.which_body, in.which_body);
    TEST_EQUAL(out.body.item1.boolean, in.body.item1.boolean);
    TEST_EQUAL(out.body.item1.integral, in.body.item1.integral);

    pbex_release(allocator, pbex_Test3_fields, &out);
    pbex_release(allocator, pbex_Test3_fields, &in);

    // test2 message option
    ostream                 = pb_ostream_from_buffer(obuf, sizeof(obuf));
    out                     = (pbex_Test3)pbex_Test3_init_default;
    out.which_body          = pbex_Test3_item2_tag;
    out.body.item2.boolean  = true;
    out.body.item2.integral = 123;

    static const uint8_t bytes[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    static const char    chars[] = "Surprise, motherfucker!";

    out.body.item2.byteArray = pbex_bytes_alloc(allocator, bytes, COUNT_OF(bytes));
    out.body.item2.string    = pbex_string_alloc(allocator, chars, -1);

    TEST_EQUAL(pbex_encode(&ostream, pbex_Test3_fields, &out), true);

    istream = pb_istream_from_buffer(obuf, ostream.bytes_written);
    in      = (pbex_Test3)pbex_Test3_init_default;
    TEST_EQUAL(pbex_decode(allocator, &istream, pbex_Test3_fields, &in), true);

    TEST_EQUAL(out.which_body, in.which_body);
    TEST_EQUAL(out.body.item2.boolean, in.body.item2.boolean);
    TEST_EQUAL(out.body.item2.integral, in.body.item2.integral);
    TEST_EQUAL(strcmp(pbex_cstring_get(out.body.item2.string), pbex_cstring_get(in.body.item2.string)), 0);
    TEST_EQUAL(memcmp(pbex_bytes_get(out.body.item2.byteArray)->data,
                      pbex_bytes_get(in.body.item2.byteArray)->data,
                      10),
               0);

    pbex_release(allocator, pbex_Test3_fields, &out);
    pbex_release(allocator, pbex_Test3_fields, &in);
}

static void _test4(pbex_allocator_t* allocator)
{
    uint8_t obuf[1024];

    pb_ostream_t ostream = pb_ostream_from_buffer(obuf, sizeof(obuf));
    pbex_Test4   out     = pbex_Test4_init_default;

    out.item = pbex_list_alloc(allocator, sizeof(pbex_Test1));

    pbex_Test1* it;

    it           = pbex_list_add_node(out.item);
    it->boolean  = true;
    it->integral = 1;

    it           = pbex_list_add_node(out.item);
    it->boolean  = false;
    it->integral = 10;

    it           = pbex_list_add_node(out.item);
    it->boolean  = true;
    it->integral = 100;

    it           = pbex_list_add_node(out.item);
    it->boolean  = false;
    it->integral = 1000;

    TEST_EQUAL(pbex_encode(&ostream, pbex_Test4_fields, &out), true);

    pb_istream_t istream = pb_istream_from_buffer(obuf, ostream.bytes_written);
    pbex_Test4   in      = pbex_Test4_init_default;
    TEST_EQUAL(pbex_decode(allocator, &istream, pbex_Test4_fields, &in), true);

    TEST_EQUAL(pbex_list_count(out.item), pbex_list_count(in.item));

    pbex_Test1* it2;
    for (it2 = pbex_list_get_node(in.item, 0), it = pbex_list_get_node(out.item, 0); it2 != NULL && it != NULL;
         it2 = pbex_list_next_node(it2), it = pbex_list_next_node(it))
    {
        TEST_EQUAL(it->boolean, it2->boolean);
        TEST_EQUAL(it->integral, it2->integral);
    }

    TEST_EQUAL(pbex_release(allocator, pbex_Test4_fields, &out), true);
    TEST_EQUAL(pbex_release(allocator, pbex_Test4_fields, &in), true);
}

static void _test5(pbex_allocator_t* allocator)
{
    uint8_t obuf[1024];

    pb_ostream_t ostream = pb_ostream_from_buffer(obuf, sizeof(obuf));
    pbex_Test5   out     = pbex_Test5_init_default;

    out.kv = pbex_list_alloc(allocator, sizeof(pbex_Test5_KvEntry));

    pbex_Test5_KvEntry* it;

    it        = pbex_list_add_node(out.kv);
    it->key   = pbex_string_alloc(allocator, "alpha", -1);
    it->value = 1;

    it        = pbex_list_add_node(out.kv);
    it->key   = pbex_string_alloc(allocator, "beta", -1);
    it->value = 2;

    it        = pbex_list_add_node(out.kv);
    it->key   = pbex_string_alloc(allocator, "gamma", -1);
    it->value = 3;

    it        = pbex_list_add_node(out.kv);
    it->key   = pbex_string_alloc(allocator, "delta", -1);
    it->value = 4;

    it        = pbex_list_add_node(out.kv);
    it->key   = pbex_string_alloc(allocator, "dzeta", -1);
    it->value = 5;

    it        = pbex_list_add_node(out.kv);
    it->key   = pbex_string_alloc(allocator, "eta", -1);
    it->value = 6;

    it        = pbex_list_add_node(out.kv);
    it->key   = pbex_string_alloc(allocator, "theta", -1);
    it->value = 7;

    TEST_EQUAL(pbex_encode(&ostream, pbex_Test5_fields, &out), true);

    pb_istream_t istream = pb_istream_from_buffer(obuf, ostream.bytes_written);
    pbex_Test5   in      = pbex_Test5_init_default;
    TEST_EQUAL(pbex_decode(allocator, &istream, pbex_Test5_fields, &in), true);

    TEST_EQUAL(pbex_list_count(out.kv), pbex_list_count(in.kv));

    pbex_Test5_KvEntry* it2;
    for (it2 = pbex_list_get_node(in.kv, 0), it = pbex_list_get_node(out.kv, 0); it2 != NULL && it != NULL;
         it2 = pbex_list_next_node(it2), it = pbex_list_next_node(it))
    {
        TEST_EQUAL(strcmp(pbex_cstring_get(it->key), pbex_cstring_get(it2->key)), 0);
        TEST_EQUAL(it->value, it2->value);
    }

    TEST_EQUAL(pbex_release(allocator, pbex_Test5_fields, &out), true);
    TEST_EQUAL(pbex_release(allocator, pbex_Test5_fields, &in), true);
}

static void _test6(pbex_allocator_t* allocator)
{
    uint8_t obuf[1024];

    pb_ostream_t ostream = pb_ostream_from_buffer(obuf, sizeof(obuf));
    pbex_Test6   out     = pbex_Test6_init_default;

    out.integrals = pbex_list_alloc(allocator, sizeof(int32_t));

    int32_t* it;

    for (int i = 1; i <= 5; i++)
    {

        it = pbex_list_add_node(out.integrals);
        TEST_EQUAL(it == NULL, false);
        *it = i;
    }

    TEST_EQUAL(pbex_encode(&ostream, pbex_Test6_fields, &out), true);

    pb_istream_t istream = pb_istream_from_buffer(obuf, ostream.bytes_written);
    pbex_Test6   in      = pbex_Test6_init_default;
    TEST_EQUAL(pbex_decode(allocator, &istream, pbex_Test6_fields, &in), true);

    TEST_EQUAL(pbex_list_count(out.integrals), pbex_list_count(in.integrals));

    int32_t* it2;
    for (it2 = pbex_list_get_node(in.integrals, 0), it = pbex_list_get_node(out.integrals, 0);
         it2 != NULL && it != NULL;
         it2 = pbex_list_next_node(it2), it = pbex_list_next_node(it))
    {
        TEST_EQUAL(*it, *it2);
    }

    TEST_EQUAL(pbex_release(allocator, pbex_Test6_fields, &out), true);
    TEST_EQUAL(pbex_release(allocator, pbex_Test6_fields, &in), true);
}

static void _test7(pbex_allocator_t* allocator)
{
    uint8_t obuf[1024];

    pb_ostream_t ostream = pb_ostream_from_buffer(obuf, sizeof(obuf));
    pbex_Test7   out     = pbex_Test7_init_default;

    out.strings = pbex_list_alloc(allocator, sizeof(pb_callback_t));

    pb_callback_t* it;

    it = pbex_list_add_node(out.strings);
    TEST_EQUAL(it == NULL, false);
    *it = pbex_string_alloc(allocator, "First", -1);

    it = pbex_list_add_node(out.strings);
    TEST_EQUAL(it == NULL, false);
    *it = pbex_string_alloc(allocator, "Second", -1);

    it = pbex_list_add_node(out.strings);
    TEST_EQUAL(it == NULL, false);
    *it = pbex_string_alloc(allocator, "Third", -1);

    TEST_EQUAL(pbex_encode(&ostream, pbex_Test7_fields, &out), true);

    pb_istream_t istream = pb_istream_from_buffer(obuf, ostream.bytes_written);
    pbex_Test7   in      = pbex_Test7_init_default;
    TEST_EQUAL(pbex_decode(allocator, &istream, pbex_Test7_fields, &in), true);

    TEST_EQUAL(pbex_list_count(out.strings), pbex_list_count(in.strings));

    pb_callback_t* it2;
    for (it2 = pbex_list_get_node(in.strings, 0), it = pbex_list_get_node(out.strings, 0); it2 != NULL && it != NULL;
         it2 = pbex_list_next_node(it2), it = pbex_list_next_node(it))
    {
        TEST_EQUAL(strcmp(pbex_cstring_get(*it), pbex_cstring_get(*it2)), 0);
    }

    TEST_EQUAL(pbex_release(allocator, pbex_Test7_fields, &out), true);
    TEST_EQUAL(pbex_release(allocator, pbex_Test7_fields, &in), true);
}

static void _test8(pbex_allocator_t* allocator)
{
}
