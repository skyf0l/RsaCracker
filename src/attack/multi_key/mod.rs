use std::sync::Arc;

use lazy_static::lazy_static;

mod common_factor;
mod common_modulus;
mod hastad_broadcast;

pub use common_factor::CommonFactorAttack;
pub use common_modulus::CommonModulusAttack;
pub use hastad_broadcast::HastadBroadcastAttack;

use crate::Attack;

lazy_static! {
    /// List of multi-key attacks
    pub static ref MULTI_KEY_ATTACKS: Vec<Arc<dyn Attack + Sync + Send>> = vec![
        Arc::new(CommonFactorAttack),
        Arc::new(CommonModulusAttack),
        Arc::new(HastadBroadcastAttack),
    ];
}
