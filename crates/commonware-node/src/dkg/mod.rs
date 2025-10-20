mod actor;
mod ingress;

pub(crate) use actor::Actor;
pub(crate) use ingress::Mailbox;

pub(crate) fn init() -> (Actor, Mailbox) {
    todo!()
}
pub(crate) struct Config {}
