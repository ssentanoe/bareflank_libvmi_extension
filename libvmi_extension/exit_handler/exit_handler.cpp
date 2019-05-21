#include <hve/arch/intel_x64/vcpu.h>
#include <bfdebug.h>
#include <bfcallonce.h>
#include "json.hpp"

using namespace bfvmm::intel_x64;
using nlohmann::json;

namespace libvmi
{

typedef enum hstatus {
	HSTATUS_SUCCESS = 0ull,
	HSTATUS_FAILURE
} hstatus_t;

typedef enum hcall {
	HCALL_ACK = 1ull,
	HCALL_GET_REGISTERS,
	HCALL_SET_REGISTERS,
	HCALL_TRANSLATE_V2P,
	HCALL_MAP_PA
} hcall_t;

bfn::once_flag flag{};
ept::mmap g_guest_map;

void create_ept()
{
	ept::identity_map(g_guest_map, MAX_PHYS_ADDR);
	::intel_x64::vmx::invept_global();
}

class vcpu : public bfvmm::intel_x64::vcpu
{

public:

	using handler_t = bool(gsl::not_null<bfvmm::intel_x64::vmcs *>);
	using handler_delegate_t = delegate<handler_t>;

	~vcpu() = default;
	vcpu(vcpuid::type id) : bfvmm::intel_x64::vcpu{id}
	{
		bfn::call_once(flag, [&] {
			create_ept();
		});

		this->set_eptp(g_guest_map);

		this->add_handler(
			intel_x64::vmcs::exit_reason::basic_exit_reason::vmcall,
			{&vcpu::vmcall_handler, this}
		);

		this->add_cpuid_handler(
			0x40001337,
			{&vcpu::cpuid_handler, this}
		);
	}

	bool cpuid_handler(vcpu_t *vcpu)
	{
		vcpu->set_rax(42);
		vcpu->set_rbx(42);
		vcpu->set_rcx(42);
		vcpu->set_rdx(42);

		return true;
	}

	bool vmcall_handler(vcpu_t *vcpu)
	{
		uint64_t hcall = vcpu->rax();

		guard_exceptions([&] 
		{
			switch(hcall)
			{
				case HCALL_ACK:
					create_ept(); // reset EPT
					bfdebug_info(0, "vmcall handled");
					break;
				case HCALL_GET_REGISTERS:
					hcall_get_register_data(vcpu);
					break;
				case HCALL_SET_REGISTERS:
					break;
				case HCALL_TRANSLATE_V2P:
					hcall_translate_v2p(vcpu);
					break;
				case HCALL_MAP_PA:
					hcall_memmap_ept(vcpu);
					break;
				default:
					break;
			};

			vcpu->set_rax(HSTATUS_SUCCESS);
		},
		[&] {
			vcpu->set_rax(HSTATUS_FAILURE);
		});

		return true;
	}

	void hcall_get_register_data(vcpu_t *vcpu)
	{
		json j;
		j["RAX"] = vcpu->rax();
		j["RBX"] = vcpu->rbx();
		j["RCX"] = vcpu->rcx();
		j["RDX"] = vcpu->rdx();
		j["R08"] = vcpu->r08();
		j["R09"] = vcpu->r09();
		j["R10"] = vcpu->r10();
		j["R11"] = vcpu->r11();
		j["R12"] = vcpu->r12();
		j["R13"] = vcpu->r13();
		j["R14"] = vcpu->r14();
		j["R15"] = vcpu->r15();
		j["RBP"] = vcpu->rbp();
		j["RSI"] = vcpu->rsi();
		j["RDI"] = vcpu->rdi();
		j["RIP"] = vcpu->rip();
		j["RSP"] = vcpu->rsp();
		j["CR0"] = vcpu->cr0();
		j["CR3"] = vcpu->cr3();
		j["CR4"] = vcpu->cr4();
		j["MSR_EFER"] = vcpu->ia32_efer();

		uintptr_t addr = vcpu->rdi();
		uint64_t size = vcpu->rsi();
		// auto omap = bfvmm::x64::unique_map<char>(addr,
		//				vcpu->cr3(),
		//				size
		//				);
		// UNFINISHED

		bfdebug_info(0, "get-registers vmcall handled");
	}

	void hcall_translate_v2p(vcpu_t *vcpu)
	{
		auto addr = vcpu->rdi();
		auto hpa = gva_to_gpa(addr);

		vcpu->set_rdi(hpa.first);

		bfdebug_info(0, "v2p vmcall handled");
	}

	void hcall_memmap_ept(vcpu_t *vcpu)
	{
		uint64_t addr = vcpu->rdi();
		uint64_t gpa2 = vcpu->rsi();

		auto hpa = gva_to_gpa(addr);
		auto gpa1 = hpa.first;

		if(g_guest_map.is_2m(gpa1))
		{
			auto gpa1_2m = bfn::upper(gpa1, ::intel_x64::ept::pd::from);
			ept::identity_map_convert_2m_to_4k(g_guest_map, gpa1_2m);
		}

		auto gpa1_4k = bfn::upper(gpa1, ::intel_x64::ept::pt::from);
		auto gpa2_4k = bfn::upper(gpa2, ::intel_x64::ept::pt::from);

		vcpu->set_rsi(gpa2_4k);

		auto pte = g_guest_map.entry(gpa1_4k);
		::intel_x64::ept::pt::entry::phys_addr::set(pte.first, gpa2_4k);
		
		// flush EPT tlb, guest TLB doesn't need to be flushed
		// as that translation hasn't changed
		::intel_x64::vmx::invept_global();

		bfdebug_info(0, "memmap ept called");
	}
};
}