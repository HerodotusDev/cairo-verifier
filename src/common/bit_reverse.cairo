#[generate_trait]
impl BitReverseU64 of BitReverseTrait {
    fn bit_reverse(self: u64) -> u64 {
        let mut num = self;
        let mut reversed: u64 = 0;
        let mut i = 0;
        loop {
            if i == 64 {
                break;
            };

            let (n, bit) = DivRem::div_rem(num, 2_u64.try_into().unwrap());
            num = n;
            reversed = reversed * 2 + bit;

            i += 1;
        };
        reversed
    }
}
