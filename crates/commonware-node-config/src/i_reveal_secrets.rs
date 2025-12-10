use std::marker::PhantomData;

use commonware_codec::Encode as _;

use super::{SigningKey, SigningShare};

pub struct IKnowWhatIamDoing;
pub struct IShouldntRevealSecrets<T, const I_KNOW_WHAT_I_AM_DOING: bool = false> {
    _phantom: PhantomData<T>,
}

impl IShouldntRevealSecrets<IKnowWhatIamDoing, false> {
    pub fn i_swear(self) -> IShouldntRevealSecrets<IKnowWhatIamDoing, true> {
        IShouldntRevealSecrets {
            _phantom: PhantomData,
        }
    }
}

pub fn i_know_what_i_am_doing() -> IShouldntRevealSecrets<IKnowWhatIamDoing, false> {
    IShouldntRevealSecrets {
        _phantom: PhantomData,
    }
}

pub fn shout_this_secret<const WRITE_THE_SECRET: bool>(
    secret: &impl Secret,
    _: IShouldntRevealSecrets<IKnowWhatIamDoing, true>,
) -> String {
    if WRITE_THE_SECRET {
        secret.shout_the_secret()
    } else {
        "".to_string()
    }
}

pub trait Secret {
    fn shout_the_secret(&self) -> String;
}

impl Secret for SigningKey {
    fn shout_the_secret(&self) -> String {
        const_hex::encode_prefixed(self.inner.encode().as_ref())
    }
}

impl Secret for SigningShare {
    fn shout_the_secret(&self) -> String {
        const_hex::encode_prefixed(self.inner.encode().as_ref())
    }
}
