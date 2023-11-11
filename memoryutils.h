#pragma once
#include <string_view>
#include <string>
#include <vector>
#include <Windows.h>
#define VPROXY(methodName, methodIndex, retType, args, ...)					\
	static constexpr std::uintptr_t vIndex_ ## methodName = methodIndex;	\
	retType methodName args noexcept { return memory_utils::vmt::call<retType>((void*)this, methodIndex, ## __VA_ARGS__); }

namespace memory_utils
{
	template<typename T>
	T* capture_interface(const std::string& module_name, const std::string& interface_name)
	{
		typedef void* (*interface_type)(const char* name, int ret);
		const auto temp = reinterpret_cast<interface_type>(GetProcAddress(GetModuleHandle(module_name.c_str()), "CreateInterface"));
		return static_cast<T*>(temp(interface_name.c_str(), 0));
	}

	template <typename T>
	static constexpr auto relative_to_absolute(uintptr_t address) noexcept
	{
		return (T)(address + 4 + *reinterpret_cast<std::int32_t*>(address));
	}

	static constexpr auto relative_to_absolute(uintptr_t address, int offset, int instruction_size = 6) noexcept
	{
		auto instruction = address + offset;

		int relativeAddress = *(int*)(instruction);
		auto realAddress = address + instruction_size + relativeAddress;
		return realAddress;
	}

	template<typename T>
	T* get_vmt_from_instruction(uintptr_t address)
	{
		uintptr_t step = 3;
		uintptr_t instructionSize = 7;
		uintptr_t instruction = address;

		uintptr_t relativeAddress = *(DWORD*)(instruction + step);
		uintptr_t realAddress = instruction + instructionSize + relativeAddress;
		return *(T**)(realAddress);
	}

	template<typename T>
	T* get_vmt_from_instruction(uintptr_t address, size_t offset)
	{
		uintptr_t step = 3;
		uintptr_t instructionSize = 7;
		uintptr_t instruction = address + offset;

		return *(T**)(relative_to_absolute(instruction, step, instructionSize));
	}

	template<typename T>
	T* get_vmt(uintptr_t address, int index, uintptr_t offset) // Address must be a VTable pointer, not a VTable !
	{
		uintptr_t step = 3;
		uintptr_t instructionSize = 7;
		uintptr_t instruction = ((*(uintptr_t**)(address))[index] + offset);

		return *(T**)(relative_to_absolute(instruction, step, instructionSize));
	}

	namespace vmt {
		// Get VMT
		static inline void** get(void* obj) {
			return *reinterpret_cast<void***>(obj);
		}

		// Get method from object by index
		template <typename T>
		static inline T get(void* obj, std::uintptr_t index) {
			return reinterpret_cast<T>(get(obj)[index]);
		}

		// Get method from vmt by index
		template <typename T>
		static inline T get(void** vmt, std::uintptr_t index) {
			return reinterpret_cast<T>(vmt[index]);
		}

		// Call method by index
		template <typename Ret_t, typename ...Args>
		static inline Ret_t call(void* obj, std::uintptr_t index, Args ...args) noexcept {
			using Function_t = Ret_t(__fastcall*)(void*, decltype(args)...);
			return get<Function_t>(obj, index)(obj, args...);
		}
	}

	std::uint8_t* pattern_scanner(const std::string& module_name, const std::string& signature) noexcept;
}