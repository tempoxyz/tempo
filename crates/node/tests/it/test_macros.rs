macro_rules! apply_raw_flag {
    ($case:ident, fee_payer) => {
        $case.fee_payer = true;
    };
    ($case:ident, access_key) => {
        $case.access_key = true;
    };
}

macro_rules! raw_case {
    ($key:ident) => {{
        let name = build_raw_name(KeyType::$key, &[]);
        RawSendTestCase {
            name,
            key_type: KeyType::$key,
            fee_payer: false,
            access_key: false,
        }
    }};
    ($key:ident, $($flag:ident),+ $(,)?) => {{
        let mut case = RawSendTestCase {
            name: String::new(),
            key_type: KeyType::$key,
            fee_payer: false,
            access_key: false,
        };
        $( apply_raw_flag!(case, $flag); )+
        let flags = [$(stringify!($flag)),+];
        case.name = build_raw_name(case.key_type, &flags);
        case
    }};
}

macro_rules! apply_send_flag {
    ($case:ident, fee_payer) => {
        $case.fee_payer = true;
    };
    ($case:ident, access_key) => {
        $case.access_key = true;
    };
    ($case:ident, batch_calls) => {
        $case.batch_calls = true;
    };
}

macro_rules! apply_send_option {
    ($case:ident, funding_amount, $value:expr) => {
        $case.funding_amount = Some($value);
    };
    ($case:ident, transfer_amount, $value:expr) => {
        $case.transfer_amount = Some($value);
    };
}

macro_rules! send_case {
    ($key:ident) => {{
        let name = build_send_name(KeyType::$key, &[], &[]);
        SendTestCase {
            name,
            key_type: KeyType::$key,
            fee_payer: false,
            access_key: false,
            batch_calls: false,
            funding_amount: None,
            transfer_amount: None,
        }
    }};
    ($key:ident, $($flag:ident),+ ; $($opt:ident = $value:expr),+ $(,)?) => {{
        let mut case = SendTestCase {
            name: String::new(),
            key_type: KeyType::$key,
            fee_payer: false,
            access_key: false,
            batch_calls: false,
            funding_amount: None,
            transfer_amount: None,
        };
        $( apply_send_flag!(case, $flag); )+
        $( apply_send_option!(case, $opt, $value); )+
        let flags = [$(stringify!($flag)),+];
        let opts = [$(stringify!($opt)),+];
        case.name = build_send_name(case.key_type, &flags, &opts);
        case
    }};
    ($key:ident, $($flag:ident),+ $(,)?) => {{
        let mut case = SendTestCase {
            name: String::new(),
            key_type: KeyType::$key,
            fee_payer: false,
            access_key: false,
            batch_calls: false,
            funding_amount: None,
            transfer_amount: None,
        };
        $( apply_send_flag!(case, $flag); )+
        let flags = [$(stringify!($flag)),+];
        case.name = build_send_name(case.key_type, &flags, &[]);
        case
    }};
}

macro_rules! apply_fill_option {
    ($case:ident, fee_token, $value:expr) => {
        $case.fee_token = Some($value);
    };
    ($case:ident, valid_before_offset, $value:expr) => {
        $case.valid_before_offset = Some($value);
    };
    ($case:ident, valid_after_offset, $value:expr) => {
        $case.valid_after_offset = Some($value);
    };
    ($case:ident, explicit_nonce, $value:expr) => {
        $case.explicit_nonce = Some($value);
    };
    ($case:ident, pre_bump_nonce, $value:expr) => {
        $case.pre_bump_nonce = Some($value);
    };
}

macro_rules! apply_fill_flag {
    ($case:ident, omit_nonce_key) => {
        $case.include_nonce_key = false;
    };
    ($case:ident, fee_payer) => {
        $case.fee_payer = true;
    };
    ($case:ident, reject) => {
        $case.expected = ExpectedOutcome::Rejection;
    };
}

macro_rules! fill_case {
    ($nonce_mode:ident $(($nonce_mode_value:expr))? , $key:ident, $($flag:ident),+ ; $($opt:ident = $value:expr),+ $(,)?) => {{
        let mut case = FillTestCase {
            name: String::new(),
            nonce_mode: NonceMode::$nonce_mode $(($nonce_mode_value))?,
            key_type: KeyType::$key,
            include_nonce_key: true,
            fee_token: None,
            fee_payer: false,
            valid_before_offset: None,
            valid_after_offset: None,
            explicit_nonce: None,
            pre_bump_nonce: None,
            expected: ExpectedOutcome::Success,
        };
        $( apply_fill_flag!(case, $flag); )+
        $( apply_fill_option!(case, $opt, $value); )+
        let flags = [$(stringify!($flag)),+];
        let opts = [$(stringify!($opt)),+];
        let mut parts = Vec::with_capacity(flags.len() + opts.len());
        parts.extend_from_slice(&flags);
        parts.extend_from_slice(&opts);
        case.name = build_fill_name(&case.nonce_mode, case.key_type, &parts);
        case
    }};
    ($nonce_mode:ident $(($nonce_mode_value:expr))? , $key:ident ; $($opt:ident = $value:expr),+ $(,)?) => {{
        let mut case = FillTestCase {
            name: String::new(),
            nonce_mode: NonceMode::$nonce_mode $(($nonce_mode_value))?,
            key_type: KeyType::$key,
            include_nonce_key: true,
            fee_token: None,
            fee_payer: false,
            valid_before_offset: None,
            valid_after_offset: None,
            explicit_nonce: None,
            pre_bump_nonce: None,
            expected: ExpectedOutcome::Success,
        };
        $( apply_fill_option!(case, $opt, $value); )+
        let opts = [$(stringify!($opt)),+];
        case.name = build_fill_name(&case.nonce_mode, case.key_type, &opts);
        case
    }};
    ($nonce_mode:ident $(($nonce_mode_value:expr))? , $key:ident $(, $flag:ident)* $(,)?) => {{
        let mut case = FillTestCase {
            name: String::new(),
            nonce_mode: NonceMode::$nonce_mode $(($nonce_mode_value))?,
            key_type: KeyType::$key,
            include_nonce_key: true,
            fee_token: None,
            fee_payer: false,
            valid_before_offset: None,
            valid_after_offset: None,
            explicit_nonce: None,
            pre_bump_nonce: None,
            expected: ExpectedOutcome::Success,
        };
        $( apply_fill_flag!(case, $flag); )*
        let flags = [$(stringify!($flag)),*];
        case.name = build_fill_name(&case.nonce_mode, case.key_type, &flags);
        case
    }};
}
