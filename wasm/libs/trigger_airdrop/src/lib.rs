//! Airdrop: mint roses on every account registration

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use dlmalloc::GlobalDlmalloc;
use iroha_trigger::prelude::*;

#[global_allocator]
static ALLOC: GlobalDlmalloc = GlobalDlmalloc;

const AIRDROP_METADATA_KEY: &str = "airdrop";

#[iroha_trigger::main]
fn main(host: Iroha, context: Context) {
    let EventBox::Data(DataEvent::Domain(DomainEvent::Account(AccountEvent::Created(account)))) =
        context.event
    else {
        dbg_panic!("only account-created events should pass");
    };
    let airdrop_metadata_key: Name = AIRDROP_METADATA_KEY.parse().unwrap();
    let airdrops = host
        .query(FindAssetsDefinitions)
        // SATO
        // .filter_with(|def| def.metadata.key(airdrop_metadata_key.clone()))
        .select_with(|def| (def.id, def.metadata.key(airdrop_metadata_key)))
        .execute_all()
        .dbg_unwrap();

    for (asset_def, amount) in airdrops {
        let amount = amount
            .try_into_any::<Numeric>()
            .dbg_expect("airdrop amount should be an integer or decimal");
        let asset = AssetId::new(asset_def, account.id().clone());
        host.submit(&Mint::asset_numeric(amount, asset))
            .dbg_expect("should mint");
    }
}
