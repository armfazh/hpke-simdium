#include <types.h>
#include <gtest/gtest.h>

std::string u8_to_string(u8 *x)
{
    std::stringstream s;
    char str[3] = {0};

    for (size_t i = 0; i < x->len; i++)
    {
        sprintf(str, "%02x", x->data[i]);
        s << str ;
    };

    return s.str();
}

testing::AssertionResult u8_cmp(
    const char *a_expr,
    const char *b_expr,
    u8 * a,
    u8 * b)
{
    if (a->len == b->len && memcmp(a->data, b->data, a->len) == 0)
    {
        return testing::AssertionSuccess();
    }
    else
    {
        return testing::AssertionFailure()
               << "mismatch " << a_expr << " and " << b_expr
               << std::endl << "got:  (" << a->len << ") " << u8_to_string(a)
               << std::endl << "want: (" << b->len << ") " << u8_to_string(b);
    }
}