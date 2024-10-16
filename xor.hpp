#pragma once

#ifndef XOR_HPP
#define XOR_HPP

#include <cstdint>

template<typename T, T v>
struct integral_constant {
    static constexpr T value = v;
    using value_type = T;
    using type = integral_constant;
    constexpr operator value_type() const noexcept { return value; }
    constexpr value_type operator()() const noexcept { return value; }
};

template<typename T>
struct remove_const { using type = T; };
template<typename T>
struct remove_const<const T> { using type = T; };
template<typename T>
using remove_const_t = typename remove_const<T>::type;

template<typename T>
struct remove_reference { using type = T; };
template<typename T>
struct remove_reference<T&> { using type = T; };
template<typename T>
struct remove_reference<T&&> { using type = T; };
template<typename T>
using remove_reference_t = typename remove_reference<T>::type;

template<typename T, T... Ints>
struct integer_sequence {
    using value_type = T;
    static constexpr size_t size() noexcept { return sizeof...(Ints); }
};

template<size_t... Ints>
using index_sequence = integer_sequence<size_t, Ints...>;

template<size_t N, size_t... Ints>
struct make_index_sequence_impl : make_index_sequence_impl<N - 1, N - 1, Ints...> {};

template<size_t... Ints>
struct make_index_sequence_impl<0, Ints...> {
    using type = index_sequence<Ints...>;
};

template<size_t N>
using make_index_sequence = typename make_index_sequence_impl<N>::type;

template<typename T>
struct make_unsigned;

template<>
struct make_unsigned<char> { using type = unsigned char; };

template<>
struct make_unsigned<wchar_t> { using type = unsigned short; };

template<typename T>
using make_unsigned_t = typename make_unsigned<T>::type;

#define xorstr(str) ::jm::xor_string([]() { return str; }, integral_constant<size_t, sizeof(str) / sizeof(*str)>{}, make_index_sequence<::jm::detail::_buffer_size<sizeof(str)>()>{})
#define xorstr_(str) ([]() { \
    static auto xor_str_instance = xorstr(str); \
    return xor_str_instance.crypt_get(); \
})()
#define XORSTR_FORCEINLINE __forceinline

namespace jm {
    namespace detail {
        constexpr uint64_t apply_xor(uint64_t value, uint64_t key) noexcept {
            return value ^ key;
        }

        constexpr uint64_t apply_not(uint64_t value) noexcept {
            return ~value;
        }

        template<size_t Size>
        XORSTR_FORCEINLINE constexpr size_t _buffer_size()
        {
            return ((Size / 16) + (Size % 16 != 0)) * 2;
        }

        template<uint32_t Seed>
        XORSTR_FORCEINLINE constexpr uint32_t key4() noexcept
        {
            uint32_t value = Seed;
            for (char c : __TIME__)
                value = static_cast<uint32_t>((value ^ c) * 16777619ull);
            return value;
        }

        template<size_t N>
        XORSTR_FORCEINLINE constexpr uint64_t key8()
        {
            constexpr auto first_part = key4<2166136261 + N>();
            constexpr auto second_part = key4<first_part>();
            return (static_cast<uint64_t>(first_part) << 32) | second_part;
        }

        XORSTR_FORCEINLINE uint64_t load_from_reg(uint64_t value) noexcept
        {
            volatile uint64_t reg = value;
            return reg;
        }

        template<size_t N, class CharT>
        XORSTR_FORCEINLINE constexpr uint64_t load_rotated_xor_not_str8(uint64_t key, size_t idx, const CharT* str) noexcept
        {
            using cast_type = typename make_unsigned<CharT>::type;
            constexpr auto value_size = sizeof(CharT);
            constexpr auto idx_offset = 8 / value_size;

            uint64_t value = 0;
            for (size_t i = 0; i < idx_offset && i + idx * idx_offset < N; ++i) {
                value |= (uint64_t{ static_cast<cast_type>(str[i + idx * idx_offset]) }
                << ((i % idx_offset) * 8 * value_size));
            }

            value = apply_xor(value, key);
            value = apply_not(value);

            return value;
        }
    }

    template<class CharT, size_t Size, class Keys, class Indices>
    class xor_string;

    template<class CharT, size_t Size, uint64_t... Keys, size_t... Indices>
    class xor_string<CharT, Size, integer_sequence<uint64_t, Keys...>, index_sequence<Indices...>> {
        constexpr static inline uint64_t alignment = ((Size > 16) ? 32 : 16);

        alignas(alignment) uint64_t _storage[sizeof...(Keys)];

    public:
        using value_type = CharT;
        using size_type = size_t;
        using pointer = CharT*;
        using const_pointer = const CharT*;

        template<class L>
        XORSTR_FORCEINLINE xor_string(L l, integral_constant<size_t, Size>, index_sequence<Indices...>) noexcept
            : _storage{ ::jm::detail::load_from_reg((integral_constant<uint64_t, detail::load_rotated_xor_not_str8<Size>(Keys, Indices, l())>::value))... }
        {}

        XORSTR_FORCEINLINE constexpr size_type size() const noexcept
        {
            return Size - 1;
        }

        XORSTR_FORCEINLINE pointer crypt_get() noexcept
        {
            alignas(alignment) uint64_t keys[]{ ::jm::detail::load_from_reg(Keys)... };

            for (size_t i = 0; i < sizeof(_storage) / sizeof(uint64_t); ++i) {
                _storage[i] = ::jm::detail::apply_not(_storage[i]);
            }

            for (size_t i = 0; i < sizeof(_storage) / sizeof(uint64_t); ++i) {
                _storage[i] ^= keys[i];
            }

            return reinterpret_cast<pointer>(_storage);
        }
    };

    template<class L, size_t Size, size_t... Indices>
    xor_string(L l, integral_constant<size_t, Size>, index_sequence<Indices...>) -> xor_string<
        remove_const_t<remove_reference_t<decltype(l()[0])>>,
        Size,
        integer_sequence<uint64_t, detail::key8<Indices>()...>,
        index_sequence<Indices...>>;
}

#endif
