#include <cstdio>
#include <cstdlib>
#include "xor.hpp"

int main() {
    printf("%s", xorstr_("Char Array:\n"));
    {
        const char* charStrings[] = {
            xorstr_("String 1"),
            xorstr_("String 2"),
            xorstr_("String 3")
        };

        for (const char* str : charStrings) {
            printf("  %s\n", str);
        }
    }

    wprintf(L"%ls", xorstr_(L"WChar Array:\n"));
    {
        const wchar_t* wcharStrings[] = {
            xorstr_(L"Wide String 1"),
            xorstr_(L"Wide String 2"),
            xorstr_(L"Wide String 3")
        };

        for (const wchar_t* str : wcharStrings) {
            wprintf(L"  %ls\n", str);
        }
    }

    system(xorstr_("pause"));

    return 0;
}
