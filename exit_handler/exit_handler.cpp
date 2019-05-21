#include <hve/arch/intel_x64/vcpu.h>
#include <bfdebug.h>
#include <bfcallonce.h>

using namespace bfvmm::intel_x64;

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
};
}