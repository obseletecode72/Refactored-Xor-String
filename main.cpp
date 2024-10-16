#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include "xor.hpp"
#include <iostream>

int main() {
    std::cout << xorstr_("Decrypted String: ") << xorstr_("Hello, World!") << std::endl;
    std::wcout << xorstr_(L"Decrypted String: ") << xorstr_(L"Hello, World!") << std::endl;

    const char* charStrings[] =
    {
        xorstr_("String 1"),
        xorstr_("String 2"),
        xorstr_("String 3"),
        xorstr_("String 4"),
        xorstr_("String 5"),
        xorstr_("String 6"),
        xorstr_("String 7"),
        xorstr_("String 8")
    };

    const wchar_t* wcharStrings[] =
    {
        xorstr_(L"WString 1"),
        xorstr_(L"WString 2"),
        xorstr_(L"WString 3"),
        xorstr_(L"WString 4"),
        xorstr_(L"WString 5"),
        xorstr_(L"WString 6"),
        xorstr_(L"WString 7"),
        xorstr_(L"WString 8")
    };

    for (auto& cstr : charStrings) {
        std::cout << cstr << std::endl;
    }

    for (auto& wstr : wcharStrings) {
        std::wcout << wstr << std::endl;
    }

    system(xorstr_("pause"));

    return 0;
}
