use cairo_verifier::air::{public_memory::Page, public_input::PublicInput};

#[starknet::interface]
trait IBootloader<TContractState> {
    fn get_bootloader_page(ref self: TContractState) -> Page;
    fn add_to_public_input(ref self: TContractState, public_input: PublicInput) -> PublicInput;
}

#[starknet::component]
mod Bootloader {
    use core::clone::Clone;
    use cairo_verifier::common::array_extend::ArrayExtendTrait;
    use cairo_verifier::air::{public_memory::Page, public_input::PublicInput};

    #[storage]
    struct Storage {}


    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        BootloaderAppend: BootloaderAppended,
    }

    #[derive(Drop, starknet::Event)]
    struct BootloaderAppended {
        page: Page
    }

    impl BootloaderImpl<
        TContractState, +HasComponent<TContractState>
    > of super::IBootloader<ComponentState<TContractState>> {
        fn get_bootloader_page(ref self: ComponentState<TContractState>) -> Page {
            array![]
        }

        fn add_to_public_input(
            ref self: ComponentState<TContractState>, public_input: PublicInput
        ) -> PublicInput {
            let mut main_page = self.get_bootloader_page();
            main_page.extend(public_input.main_page.span());
            self.emit(BootloaderAppended { page: main_page.clone() });
            PublicInput {
                log_n_steps: public_input.log_n_steps,
                range_check_min: public_input.range_check_min,
                range_check_max: public_input.range_check_max,
                layout: public_input.layout,
                dynamic_params: public_input.dynamic_params,
                segments: public_input.segments,
                padding_addr: public_input.padding_addr,
                padding_value: public_input.padding_value,
                main_page,
                continuous_page_headers: public_input.continuous_page_headers,
            }
        }
    }
}
