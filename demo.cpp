#include "obfuscate.h"

#include <atomic>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace
{
	constexpr unsigned char kDecodeMask = 0x5A;

	int g_failures = 0;
	std::mutex g_shared_mutex;

	static const char* g_global_pointer = AY_OBFUSCATE("DEMO::GLOBAL::POINTER");

	unsigned char runtime_decode_mask()
	{
		volatile unsigned char mask = kDecodeMask;
		return mask;
	}

	template <size_t N>
	std::string decode_text(const unsigned char(&encoded)[N])
	{
		std::string text;
		text.reserve(N);

		const auto mask = runtime_decode_mask();
		for (size_t i = 0; i < N; ++i)
		{
			text.push_back(static_cast<char>(encoded[i] ^ mask));
		}

		return text;
	}

	template <size_t N>
	std::wstring decode_wide_text(const unsigned char(&encoded)[N])
	{
		std::wstring text;
		text.reserve(N);

		const auto mask = runtime_decode_mask();
		for (size_t i = 0; i < N; ++i)
		{
			text.push_back(static_cast<wchar_t>(encoded[i] ^ mask));
		}

		return text;
	}

	void expect(bool condition, const char* label)
	{
		if (!condition)
		{
			std::cerr << "[FAIL] " << label << std::endl;
			++g_failures;
		}
	}

	void check_basic_macro_usage()
	{
		const unsigned char expected_data[] = {
			0x1E, 0x1F, 0x17, 0x15, 0x60, 0x60, 0x18, 0x1B, 0x09, 0x13, 0x19, 0x60, 0x60, 0x12, 0x1F, 0x16, 0x16, 0x15
		};
		const auto expected = decode_text(expected_data);
		auto demo = AY_OBFUSCATE("DEMO::BASIC::HELLO");
		expect(demo.is_encrypted(), "basic macro starts encrypted");

		demo.decrypt();
		expect(std::string(demo) == expected, "basic macro decrypts correctly");

		demo.encrypt();
		expect(demo.is_encrypted(), "basic macro re-encrypts");

		expect(std::string(demo) == expected, "basic macro decrypts on implicit conversion");
		expect(!demo.is_encrypted(), "basic macro updates state after implicit conversion");
	}

	void check_custom_key_usage()
	{
		const unsigned char expected_data[] = {
			0x1E, 0x1F, 0x17, 0x15, 0x60, 0x60, 0x19, 0x0F, 0x09, 0x0E, 0x15, 0x17, 0x60, 0x60, 0x11, 0x1F, 0x03
		};
		const auto expected = decode_text(expected_data);
		auto keyed = AY_OBFUSCATE_KEY("DEMO::CUSTOM::KEY", 0xf8d3481a4bc32d83ull);
		expect(std::string(keyed) == expected, "custom key usage");
	}

	void check_direct_api_usage()
	{
		const unsigned char expected_data[] = {
			0x1E, 0x1F, 0x17, 0x15, 0x60, 0x60, 0x1E, 0x13, 0x08, 0x1F, 0x19, 0x0E, 0x60, 0x60, 0x1B, 0x0A, 0x13
		};
		const auto expected = decode_text(expected_data);
		constexpr auto obfuscator = ay::make_obfuscator("DEMO::DIRECT::API");
		auto direct = ay::obfuscated_data<obfuscator.size(), obfuscator.key()>(obfuscator);
		expect(std::string(direct) == expected, "direct API usage");
	}

	void check_buffer_api_usage()
	{
		const unsigned char expected_data[] = {
			0x08, 0x1B, 0x0D, 0x1E, 0x1F, 0x17, 0x15, 0x7B
		};
		const auto expected = decode_text(expected_data);
		constexpr auto raw_obfuscator = ay::obfuscator<8, AY_OBFUSCATE_DEFAULT_KEY>("RAWDEMO!");
		auto raw = ay::obfuscated_data<raw_obfuscator.size(), raw_obfuscator.key()>(raw_obfuscator);

		auto* data = raw.data();
		expect(raw.size() == 8ull, "buffer API preserves raw size");
		expect(std::string(data, data + raw.size()) == expected, "buffer API exposes fixed-width data safely");
	}

	void check_pointer_forms()
	{
		const unsigned char global_data[] = {
			0x1E, 0x1F, 0x17, 0x15, 0x60, 0x60, 0x1D, 0x16, 0x15, 0x18, 0x1B, 0x16, 0x60, 0x60, 0x0A, 0x15, 0x13, 0x14, 0x0E, 0x1F, 0x08
		};
		const unsigned char local_data[] = {
			0x1E, 0x1F, 0x17, 0x15, 0x60, 0x60, 0x16, 0x15, 0x19, 0x1B, 0x16, 0x60, 0x60, 0x0A, 0x15, 0x13, 0x14, 0x0E, 0x1F, 0x08
		};
		const unsigned char temporary_data[] = {
			0x1E, 0x1F, 0x17, 0x15, 0x60, 0x60, 0x0E, 0x1F, 0x17, 0x0A, 0x15, 0x08, 0x1B, 0x08, 0x03, 0x60, 0x60, 0x09, 0x0E, 0x08, 0x13, 0x14, 0x1D
		};
		const auto global_expected = decode_text(global_data);
		const auto local_expected = decode_text(local_data);
		const auto temporary_expected = decode_text(temporary_data);

		expect(std::string(g_global_pointer) == global_expected, "global pointer form");

		const char* local = AY_OBFUSCATE("DEMO::LOCAL::POINTER");
		expect(std::string(local) == local_expected, "local pointer form");

		std::string temporary(AY_OBFUSCATE("DEMO::TEMPORARY::STRING"));
		expect(temporary == temporary_expected, "temporary string form");
	}

	void check_wide_literal_usage()
	{
		const unsigned char expected_data[] = {
			0x1E, 0x1F, 0x17, 0x15, 0x60, 0x60, 0x0D, 0x13, 0x1E, 0x1F, 0x60, 0x60, 0x16, 0x13, 0x0E, 0x1F, 0x08, 0x1B, 0x16
		};
		const auto expected = decode_wide_text(expected_data);
		auto wide = AY_OBFUSCATE(L"DEMO::WIDE::LITERAL");
		wide.decrypt();
		expect(std::wstring(wide) == expected, "wide literal usage");
		wide.encrypt();
		expect(wide.is_encrypted(), "wide literal re-encrypts");
	}

	void local_copy_worker(std::atomic<int>& passes)
	{
		const unsigned char expected_data[] = {
			0x1E, 0x1F, 0x17, 0x15, 0x60, 0x60, 0x0E, 0x12, 0x08, 0x1F, 0x1B, 0x1E, 0x60, 0x60, 0x16, 0x15, 0x19, 0x1B, 0x16, 0x60, 0x60, 0x19, 0x15, 0x0A, 0x03
		};
		const auto expected = decode_text(expected_data);

		for (int i = 0; i < 64; ++i)
		{
			auto local = AY_OBFUSCATE("DEMO::THREAD::LOCAL::COPY");
			local.decrypt();
			if (std::string(local) == expected)
			{
				++passes;
			}
			local.encrypt();
		}
	}

	void shared_reference_worker(std::atomic<int>& passes)
	{
		const unsigned char expected_data[] = {
			0x1E, 0x1F, 0x17, 0x15, 0x60, 0x60, 0x0E, 0x12, 0x08, 0x1F, 0x1B, 0x1E, 0x60, 0x60, 0x09, 0x12, 0x1B, 0x08, 0x1F, 0x1E, 0x60, 0x60, 0x08, 0x1F, 0x1C, 0x1F, 0x08, 0x1F, 0x14, 0x19, 0x1F
		};
		const auto expected = decode_text(expected_data);

		for (int i = 0; i < 32; ++i)
		{
			std::lock_guard<std::mutex> lock(g_shared_mutex);
			auto& shared = AY_OBFUSCATE("DEMO::THREAD::SHARED::REFERENCE");
			shared.decrypt();
			if (std::string(shared) == expected)
			{
				++passes;
			}
			shared.encrypt();
		}
	}

	void check_threaded_usage()
	{
		std::atomic<int> local_passes{ 0 };
		std::thread local_thread_1(local_copy_worker, std::ref(local_passes));
		std::thread local_thread_2(local_copy_worker, std::ref(local_passes));
		local_thread_1.join();
		local_thread_2.join();
		expect(local_passes == 128, "threaded local-copy usage");

		std::atomic<int> shared_passes{ 0 };
		std::thread shared_thread_1(shared_reference_worker, std::ref(shared_passes));
		std::thread shared_thread_2(shared_reference_worker, std::ref(shared_passes));
		shared_thread_1.join();
		shared_thread_2.join();
		expect(shared_passes == 64, "threaded shared-reference usage with locking");
	}

	void print_configuration()
	{
		std::cout
			<< "Obfuscate demo"
			<< " | freestanding=" << AY_OBFUSCATE_FREESTANDING
			<< " | thread_local=" << AY_OBFUSCATE_USE_THREAD_LOCAL
			<< " | zero_after_destruction=" << AY_OBFUSCATE_ZERO_AFTER_DESTRUCTION
			<< std::endl;
	}
}

int main()
{
	print_configuration();

	check_basic_macro_usage();
	check_custom_key_usage();
	check_direct_api_usage();
	check_buffer_api_usage();
	check_pointer_forms();
	check_wide_literal_usage();
	check_threaded_usage();

	if (g_failures != 0)
	{
		std::cerr << "Demo failed with " << g_failures << " error(s)." << std::endl;
		return 1;
	}

	std::cout << "All demo checks passed." << std::endl;
	return 0;
}
