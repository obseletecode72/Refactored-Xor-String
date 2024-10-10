#include <cstdio>
#include <cstdlib>
#include "xor.hpp"

int main() {
    // Use RXor for all string literals
    printf("%s", RXor("Char Array:\n"));
    {
        const char* charStrings[] = {
            RXor("String 1"),
            RXor("String 2"),
            RXor("String 3")
        };

        for (const char* str : charStrings) {
            printf("  %s\n", str);
        }
    }

    wprintf(L"%ls", RXor(L"WChar Array:\n"));
    {
        const wchar_t* wcharStrings[] = {
            RXor(L"Wide String 1"),
            RXor(L"Wide String 2"),
            RXor(L"Wide String 3")
        };

        for (const wchar_t* str : wcharStrings) {
            wprintf(L"  %ls\n", str);
        }
    }

    system(RXor("pause"));

    return 0;
}
