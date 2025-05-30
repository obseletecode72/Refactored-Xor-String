#pragma once

#ifndef XOR_HPP
#define XOR_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <utility>
#include <type_traits>


#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif


template<typename T, T v>
struct integral_constant {
    static constexpr T value = v;
    using value_type = T;
    using type = integral_constant;
    constexpr operator value_type() const noexcept { return value; }
    constexpr value_type operator()() const noexcept { return value; }
};

template<typename T> struct remove_const { using type = T; };
template<typename T> struct remove_const<const T> { using type = T; };
template<typename T> using remove_const_t = typename remove_const<T>::type;

template<typename T> struct remove_reference { using type = T; };
template<typename T> struct remove_reference<T&> { using type = T; };
template<typename T> struct remove_reference<T&&> { using type = T; };
template<typename T> using remove_reference_t = typename remove_reference<T>::type;

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

template<> struct make_unsigned<char> { using type = unsigned char; };
template<> struct make_unsigned<wchar_t> { using type = unsigned short; };
template<typename T> using make_unsigned_t = typename make_unsigned<T>::type;

#ifndef XORSTR_FORCEINLINE
#ifdef _MSC_VER
#define XORSTR_FORCEINLINE __forceinline
#elif defined(__GNUC__) || defined(__clang__)
#define XORSTR_FORCEINLINE __attribute__((always_inline)) inline
#else
#define XORSTR_FORCEINLINE inline
#endif
#endif

namespace jm {
    namespace detail {
        XORSTR_FORCEINLINE constexpr uint64_t apply_xor(uint64_t value, uint64_t key) noexcept {
            return value ^ key;
        }

        XORSTR_FORCEINLINE constexpr uint64_t apply_not(uint64_t value) noexcept {
            return ~value;
        }

        template<size_t TotalBytesOfString>
        XORSTR_FORCEINLINE constexpr size_t _buffer_size_in_uint64_blocks() {
            constexpr size_t bytes_per_block = sizeof(uint64_t);
            size_t num_blocks = (TotalBytesOfString + bytes_per_block - 1) / bytes_per_block;
            return num_blocks > 0 ? num_blocks : 1;
        }

        template<uint32_t Seed>
        XORSTR_FORCEINLINE constexpr uint32_t key4() noexcept {
            uint32_t value = Seed;
            for (char c : __TIME__)
                value = static_cast<uint32_t>((value ^ static_cast<uint32_t>(c)) * 16777619ull);
            return value;
        }

        template<size_t N_Index>
        XORSTR_FORCEINLINE constexpr uint64_t key8() {
            constexpr auto first_part = key4<2166136261 + N_Index>();
            constexpr auto second_part = key4<first_part>();
            return (static_cast<uint64_t>(first_part) << 32) | second_part;
        }

        XORSTR_FORCEINLINE uint64_t load_from_reg(uint64_t value) noexcept {
            volatile uint64_t reg = value;
            return reg;
        }

        template<size_t N_CharsIncludingNull, class CharT_LRS>
        XORSTR_FORCEINLINE constexpr uint64_t load_rotated_xor_not_str8(uint64_t key, size_t block_idx, const CharT_LRS* str_ptr) noexcept {
            using cast_type = ::make_unsigned_t<CharT_LRS>;
            constexpr auto char_size_bytes = sizeof(CharT_LRS);
            constexpr auto chars_per_uint64 = sizeof(uint64_t) / char_size_bytes;

            uint64_t current_block_value = 0;
            for (size_t i = 0; i < chars_per_uint64; ++i) {
                size_t current_char_idx_in_string = i + block_idx * chars_per_uint64;
                if (current_char_idx_in_string < N_CharsIncludingNull) {
                    current_block_value |= (uint64_t{ static_cast<cast_type>(str_ptr[current_char_idx_in_string]) } << (i * char_size_bytes * 8));
                }
            }
            current_block_value = apply_xor(current_block_value, key);
            current_block_value = apply_not(current_block_value);
            return current_block_value;
        }
    }

    template<class char_t_tpl_param, size_t size_tpl_param, class keys_seq_tpl_param, class indices_seq_tpl_param, class lambda_provider_type_tpl_param>
    class xor_string;

    template<class char_t_param, size_t size_param, typename underlying_xor_string_type_ref_param>
    class scoped_decrypted_buffer {
    public:
        using char_type = char_t_param;
        using const_pointer = const char_type*;

        explicit scoped_decrypted_buffer(underlying_xor_string_type_ref_param instance_ref)
            : local_buffer_{}, is_valid_{ true } {
            const_pointer decrypted_data_from_static_instance = instance_ref.crypt_get();
            for (size_t i = 0; i < size_param; ++i) {
                local_buffer_[i] = decrypted_data_from_static_instance[i];
            }
            instance_ref.force_recrypt();
        }

        ~scoped_decrypted_buffer() {
            if (is_valid_) {
                for (size_t i = 0; i < size_param; ++i) {
                    volatile char_type* p = &local_buffer_[i];
                    *p = static_cast<char_type>(0); // Limpa o buffer
                }
            }
        }

        scoped_decrypted_buffer(const scoped_decrypted_buffer& other)
            : local_buffer_(other.local_buffer_), is_valid_(other.is_valid_) {
        }

        scoped_decrypted_buffer& operator=(const scoped_decrypted_buffer& other) {
            if (this != &other) {
                if (is_valid_) {
                    for (size_t i = 0; i < size_param; ++i) {
                        volatile char_type* p = &local_buffer_[i];
                        *p = static_cast<char_type>(0); // Limpa o buffer atual
                    }
                }
                local_buffer_ = other.local_buffer_;
                is_valid_ = other.is_valid_;
            }
            return *this;
        }


        scoped_decrypted_buffer(scoped_decrypted_buffer&& other) noexcept
            : local_buffer_(other.local_buffer_), is_valid_{ other.is_valid_ } {
            other.is_valid_ = false;
        }

        scoped_decrypted_buffer& operator=(scoped_decrypted_buffer&& other) noexcept {
            if (this != &other) {
                if (is_valid_) {
                    for (size_t i = 0; i < size_param; ++i) {
                        volatile char_type* p = &local_buffer_[i];
                        *p = static_cast<char_type>(0); // Limpa o buffer atual
                    }
                }
                local_buffer_ = other.local_buffer_;
                is_valid_ = other.is_valid_;
                other.is_valid_ = false;
            }
            return *this;
        }

        const_pointer get() const {
            return is_valid_ ? local_buffer_.data() : nullptr;
        }

        operator const_pointer() const {
            return get();
        }

    private:
        std::array<char_type, size_param> local_buffer_;
        bool is_valid_;
    };


    template<class CharT_tpl_param, size_t Size_tpl_param, uint64_t... Keys_p_param, size_t... Indices_p_param, class LambdaProviderType_tpl_param>
    class xor_string<CharT_tpl_param, Size_tpl_param,
        ::integer_sequence<uint64_t, Keys_p_param...>,
        ::index_sequence<Indices_p_param...>,
        LambdaProviderType_tpl_param>
    {
        constexpr static inline uint64_t alignment = (((Size_tpl_param * sizeof(CharT_tpl_param)) > 16) ? 32 : 16);
        alignas(alignment) mutable uint64_t _storage[sizeof...(Indices_p_param)];
        mutable bool decrypted;

        static XORSTR_FORCEINLINE constexpr auto make_encrypted_blocks_array() {
            constexpr LambdaProviderType_tpl_param lambda_obj{};
            constexpr auto str_literal_ptr = lambda_obj();
            return std::array<uint64_t, sizeof...(Indices_p_param)>{
                ::jm::detail::load_rotated_xor_not_str8<Size_tpl_param>(
                    ::jm::detail::key8<Indices_p_param>(),
                    Indices_p_param,
                    str_literal_ptr
                )...
            };
        }

        constexpr static std::array<uint64_t, sizeof...(Indices_p_param)> _encrypted_blocks = make_encrypted_blocks_array();

        XORSTR_FORCEINLINE void _decrypt_internal() const noexcept {
            if (!decrypted) {
                for (size_t i = 0; i < sizeof...(Indices_p_param); ++i) {
                    _storage[i] = ::jm::detail::load_from_reg(_encrypted_blocks[i]);
                }

                constexpr uint64_t current_keys_arr[] = { Keys_p_param... };
                for (size_t i = 0; i < sizeof...(Indices_p_param); ++i) {
                    _storage[i] = ::jm::detail::apply_not(_storage[i]);
                    _storage[i] = ::jm::detail::apply_xor(_storage[i], ::jm::detail::load_from_reg(current_keys_arr[i]));
                }
                decrypted = true;
            }
        }

        XORSTR_FORCEINLINE void _recrypt_internal() noexcept {
            if (decrypted) {
                constexpr uint64_t current_keys_arr[] = { Keys_p_param... };
                for (size_t i = 0; i < sizeof...(Indices_p_param); ++i) {
                    _storage[i] = ::jm::detail::apply_xor(_storage[i], ::jm::detail::load_from_reg(current_keys_arr[i]));
                    _storage[i] = ::jm::detail::apply_not(_storage[i]);
                }
                decrypted = false;
            }
        }

    public:
        using value_type = CharT_tpl_param;
        using size_type = size_t;
        using pointer = CharT_tpl_param*;
        using const_pointer = const CharT_tpl_param*;

        XORSTR_FORCEINLINE constexpr xor_string(
            LambdaProviderType_tpl_param,
            ::integral_constant<size_t, Size_tpl_param>,
            ::index_sequence<Indices_p_param...>
        ) noexcept : decrypted(false) {
        }

        XORSTR_FORCEINLINE ~xor_string() noexcept {
            _recrypt_internal();
        }

        XORSTR_FORCEINLINE constexpr size_type size() const noexcept {
            return Size_tpl_param - 1;
        }

        XORSTR_FORCEINLINE const_pointer crypt_get() const noexcept {
            _decrypt_internal();
            return reinterpret_cast<const_pointer>(_storage);
        }

        XORSTR_FORCEINLINE void force_recrypt() noexcept {
            _recrypt_internal();
        }
    };

    template<class LambdaStrProvider_cdt, size_t StrNWithNull_cdt, size_t... IdxsForGen_cdt>
    xor_string(LambdaStrProvider_cdt l_provider_obj_cdt, ::integral_constant<size_t, StrNWithNull_cdt> size_holder_cdt, ::index_sequence<IdxsForGen_cdt...> idx_seq_holder_cdt)
        -> xor_string<
        ::remove_const_t<::remove_reference_t<decltype(l_provider_obj_cdt()[0])>>,
        StrNWithNull_cdt,
        ::integer_sequence<uint64_t, ::jm::detail::key8<IdxsForGen_cdt>()...>,
        ::index_sequence<IdxsForGen_cdt...>,
        LambdaStrProvider_cdt
        >;
}

#define xorstr(str_literal) \
    ::jm::xor_string( \
        []() { return str_literal; }, \
        ::integral_constant<size_t, sizeof(str_literal) / sizeof(str_literal[0])>{}, \
        ::make_index_sequence<::jm::detail::_buffer_size_in_uint64_blocks<sizeof(str_literal)>()>() \
    )

#undef xorstr_
#define xorstr_(str_literal) \
    ([&]() { \
        using char_type_macro_ = ::remove_const_t<::remove_reference_t<decltype(str_literal[0])>>; \
        constexpr size_t str_size_macro_ = sizeof(str_literal) / sizeof(str_literal[0]); \
        \
        static auto xor_str_instance_ = ::jm::xor_string( \
            []() { return str_literal; }, \
            ::integral_constant<size_t, str_size_macro_>{}, \
            ::make_index_sequence<::jm::detail::_buffer_size_in_uint64_blocks<sizeof(str_literal)>()>() \
        ); \
        return ::jm::scoped_decrypted_buffer< \
            char_type_macro_, \
            str_size_macro_, \
            decltype(xor_str_instance_) \
        >(xor_str_instance_); \
    }())

#endif
