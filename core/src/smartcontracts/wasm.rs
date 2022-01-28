//! This module contains logic related to executing smartcontracts via `WebAssembly` VM
//! Smartcontracts can be written in Rust, compiled to wasm format and submitted in a transaction

use config::Configuration;
use eyre::WrapErr;
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use parity_scale_codec::{Decode, Encode};
use wasmtime::{Caller, Config, Engine, Linker, Module, Store, Trap, TypedFunc};

use crate::{
    smartcontracts::{Execute, ValidQuery},
    wsv::{WorldStateView, WorldTrait},
};

type WasmUsize = u32;

const WASM_ALLOC_FN: &str = "_iroha_wasm_alloc";
const WASM_MEMORY_NAME: &str = "memory";
const WASM_MAIN_FN_NAME: &str = "_iroha_wasm_main";
const EXECUTE_ISI_FN_NAME: &str = "execute_instruction";
const EXECUTE_QUERY_FN_NAME: &str = "execute_query";

/// `WebAssembly` execution error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Engine or linker could not be created
    #[error("Runtime initialization failure")]
    Initialization(#[source] anyhow::Error),
    /// Module could not be compiled or instantiated
    #[error("Module instantiation failure")]
    Instantiation(#[source] anyhow::Error),
    /// Expected named export not found in module
    #[error("Named export not found")]
    ExportNotFound(#[source] anyhow::Error),
    /// Call to function exported from module failed
    #[error("Exported function call failed")]
    ExportFnCall(#[from] Trap),
    /// Some other error happened
    #[error(transparent)]
    Other(eyre::Error),
}

struct State<'a, W: WorldTrait> {
    wsv: &'a WorldStateView<W>,
    account_id: AccountId,

    /// Number of instructions in the smartcontract
    instruction_count: u64,

    /// Max number of instructions in the smartcontract
    max_instruction_count: u64,
}

impl<'a, W: WorldTrait> State<'a, W> {
    fn new(wsv: &'a WorldStateView<W>, account_id: AccountId, max_instruction_count: u64) -> Self {
        Self {
            wsv,
            account_id,
            instruction_count: 0,
            max_instruction_count,
        }
    }

    /// Checks if number of instructions in wasm smartcontract exceeds maximum
    ///
    /// # Errors
    ///
    /// If number of instructions exceeds maximum
    #[inline]
    fn check_instruction_len(&self) -> Result<(), Trap> {
        if self.instruction_count > self.max_instruction_count {
            return Err(Trap::new(format!(
                "Number of instructions exceeds maximum({})",
                self.max_instruction_count
            )));
        }

        Ok(())
    }
}

/// `WebAssembly` virtual machine
pub struct Runtime<'a, W: WorldTrait> {
    engine: Engine,
    linker: Linker<State<'a, W>>,
    config: Configuration,
}

impl<'a, W: WorldTrait> Runtime<'a, W> {
    /// `Runtime` constructor with default configuration.
    ///
    /// # Errors
    ///
    /// If unable to construct runtime
    pub fn new() -> Result<Self, Error> {
        let engine = Self::create_engine()?;
        let config = Configuration::default();

        let linker = Self::create_linker(&engine)?;

        Ok(Self {
            engine,
            linker,
            config,
        })
    }

    /// `Runtime` constructor.
    ///
    /// # Errors
    ///
    /// See [`Runtime::new`]
    pub fn from_configuration(config: Configuration) -> Result<Self, Error> {
        Ok(Self {
            config,
            ..Runtime::new()?
        })
    }

    fn create_config() -> Config {
        let mut config = Config::new();
        config.consume_fuel(true);
        //config.cache_config_load_default();
        config
    }

    fn create_engine() -> Result<Engine, Error> {
        Engine::new(&Self::create_config()).map_err(Error::Initialization)
    }

    /// Host defined function which executes query. When calling this function, module
    /// serializes query to linear memory and provides offset and length as parameters
    ///
    /// # Warning
    ///
    /// This function doesn't take ownership of the provided allocation
    /// but it does transfer ownership of the result to the caller
    ///
    /// # Errors
    ///
    /// If decoding or execution of the query fails
    fn execute_query(
        mut caller: Caller<State<W>>,
        offset: WasmUsize,
        len: WasmUsize,
    ) -> Result<(WasmUsize, WasmUsize), Trap> {
        let alloc_fn = Self::get_alloc_fn(&mut caller)?;
        let memory = Self::get_memory(&mut caller)?;

        // Accessing memory as a byte slice to avoid the use of unsafe
        let query_mem_range = offset as usize..(offset + len) as usize;
        let mut query_bytes = &memory.data(&caller)[query_mem_range];
        let query =
            QueryBox::decode(&mut query_bytes).map_err(|error| Trap::new(error.to_string()))?;

        let res_bytes = query
            .execute(caller.data().wsv)
            .map_err(|e| Trap::new(e.to_string()))?
            .encode();

        let res_bytes_len: WasmUsize = {
            let res_bytes_len: Result<WasmUsize, _> = res_bytes.len().try_into();
            res_bytes_len.map_err(|error| Trap::new(error.to_string()))?
        };

        let res_offset = {
            let res_offset = alloc_fn
                .call(&mut caller, res_bytes_len)
                .map_err(|e| Trap::new(e.to_string()))?;

            let res_mem_range = res_offset as usize..res_offset as usize + res_bytes.len();
            memory.data_mut(&mut caller)[res_mem_range].copy_from_slice(&res_bytes[..]);

            res_offset
        };

        Ok((res_offset, res_bytes_len))
    }

    /// Host defined function which executes ISI. When calling this function, module
    /// serializes ISI to linear memory and provides offset and length as parameters
    ///
    /// # Warning
    ///
    /// This function doesn't take ownership of the provided allocation
    /// but it does tranasfer ownership of the result to the caller
    ///
    /// # Errors
    ///
    /// If decoding or execution of the ISI fails
    fn execute_instruction(
        mut caller: Caller<State<W>>,
        offset: WasmUsize,
        len: WasmUsize,
    ) -> Result<(), Trap> {
        let memory = Self::get_memory(&mut caller)?;

        // Accessing memory as a byte slice to avoid the use of unsafe
        let isi_mem_range = offset as usize..(offset + len) as usize;
        let mut isi_bytes = &memory.data(&caller)[isi_mem_range];
        let instruction =
            Instruction::decode(&mut isi_bytes).map_err(|error| Trap::new(error.to_string()))?;

        caller.data_mut().instruction_count += 1;
        caller.data().check_instruction_len()?;

        instruction
            .execute(caller.data().account_id.clone(), caller.data().wsv)
            .map_err(|error| Trap::new(error.to_string()))?;

        Ok(())
    }

    fn create_linker(engine: &Engine) -> Result<Linker<State<'a, W>>, Error> {
        let mut linker = Linker::new(engine);

        linker
            .func_wrap("iroha", EXECUTE_ISI_FN_NAME, Self::execute_instruction)
            .map_err(Error::Initialization)?;

        linker
            .func_wrap("iroha", EXECUTE_QUERY_FN_NAME, Self::execute_query)
            .map_err(Error::Initialization)?;

        Ok(linker)
    }

    fn get_alloc_fn(
        caller: &mut Caller<State<W>>,
    ) -> Result<TypedFunc<WasmUsize, WasmUsize>, Trap> {
        caller
            .get_export(WASM_ALLOC_FN)
            .ok_or_else(|| Trap::new(format!("{}: export not found", WASM_ALLOC_FN)))?
            .into_func()
            .ok_or_else(|| Trap::new(format!("{}: not a function", WASM_ALLOC_FN)))?
            .typed::<WasmUsize, WasmUsize, _>(caller)
            .map_err(|_error| Trap::new(format!("{}: unexpected declaration", WASM_ALLOC_FN)))
    }

    fn get_memory(caller: &mut Caller<State<W>>) -> Result<wasmtime::Memory, Trap> {
        caller
            .get_export(WASM_MEMORY_NAME)
            .ok_or_else(|| Trap::new(format!("{}: export not found", WASM_MEMORY_NAME)))?
            .into_memory()
            .ok_or_else(|| Trap::new(format!("{}: not a memory", WASM_MEMORY_NAME)))
    }

    /// Executes the given wasm smartcontract
    ///
    /// # Errors
    ///
    /// If unable to construct wasm module or instance of wasm module, if unable to add fuel limit,
    /// if unable to find expected exports(main, memory, allocator) or if the execution of the
    /// smartcontract fails
    pub fn execute(
        &mut self,
        wsv: &WorldStateView<W>,
        account_id: AccountId,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let account_bytes = account_id.encode();

        let module = Module::new(&self.engine, bytes).map_err(Error::Instantiation)?;
        let mut store = Store::new(
            &self.engine,
            State::new(wsv, account_id, self.config.max_instruction_count),
        );
        store
            .add_fuel(self.config.fuel_limit)
            .map_err(Error::Instantiation)?;

        let instance = self
            .linker
            .instantiate(&mut store, &module)
            .map_err(Error::Instantiation)?;
        let alloc_fn = instance
            .get_typed_func::<WasmUsize, WasmUsize, _>(&mut store, WASM_ALLOC_FN)
            .map_err(Error::ExportNotFound)?;

        let memory = instance
            .get_memory(&mut store, WASM_MEMORY_NAME)
            .ok_or_else(|| {
                Error::ExportNotFound(anyhow::Error::msg(format!(
                    "{}: export not found or not a memory",
                    WASM_MEMORY_NAME
                )))
            })?;

        let account_bytes_len = account_bytes
            .len()
            .try_into()
            .wrap_err(format!(
                "Encoded account ID has size larger than {}::MAX",
                std::any::type_name::<WasmUsize>()
            ))
            .map_err(Error::Other)?;

        let account_offset = {
            let acc_offset = alloc_fn
                .call(&mut store, account_bytes_len)
                .map_err(Error::ExportFnCall)?;

            let acc_mem_range = acc_offset as usize..acc_offset as usize + account_bytes.len();
            memory.data_mut(&mut store)[acc_mem_range].copy_from_slice(&account_bytes[..]);

            acc_offset
        };

        let main_fn = instance
            .get_typed_func::<(WasmUsize, WasmUsize), (), _>(&mut store, WASM_MAIN_FN_NAME)
            .map_err(Error::ExportNotFound)?;

        // NOTE: This function takes ownership of the pointer
        main_fn
            .call(&mut store, (account_offset, account_bytes_len))
            .map_err(Error::ExportFnCall)?;

        Ok(())
    }
}

/// This module contains all configuration related logic.
pub mod config {
    use iroha_config::derive::Configurable;
    use iroha_data_model::transaction;
    use serde::{Deserialize, Serialize};

    const DEFAULT_FUEL_LIMIT: u64 = 100_000;

    /// [`WebAssembly Runtime`](super::Runtime) configuration.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Configurable)]
    #[config(env_prefix = "WASM_")]
    #[serde(rename_all = "UPPERCASE", default)]
    pub struct Configuration {
        /// Every WASM instruction costs approximately 1 unit of fuel. See
        /// [`wasmtime` reference](https://docs.rs/wasmtime/0.29.0/wasmtime/struct.Store.html#method.add_fuel)
        pub fuel_limit: u64,

        /// Maximum number of instructions per transaction
        pub max_instruction_count: u64,
    }

    impl Default for Configuration {
        fn default() -> Self {
            Configuration {
                fuel_limit: DEFAULT_FUEL_LIMIT,
                max_instruction_count: transaction::DEFAULT_MAX_INSTRUCTION_NUMBER,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use iroha_crypto::KeyPair;

    use super::*;
    use crate::{DomainsMap, PeersIds, World};

    fn world_with_test_account(account_id: AccountId) -> World {
        let domain_id = account_id.domain_id.clone();
        let public_key = KeyPair::generate().unwrap().public_key;
        let account = Account::with_signatory(account_id, public_key);
        let domain = Domain::with_accounts(domain_id.name.as_ref(), std::iter::once(account));

        let domains = DomainsMap::new();
        domains.insert(domain_id, domain);
        World::with(domains, PeersIds::new())
    }

    fn memory_and_alloc(isi_hex: &str) -> String {
        format!(
            r#"
            ;; Embed ISI into WASM binary memory
            (memory (export "{memory_name}") 1)
            (data (i32.const 0) "{isi_hex}")

            ;; Variable which tracks total allocated size
            (global $mem_size (mut i32) i32.const {isi_len})

            ;; Export mock allocator to host. This allocator never frees!
            (func (export "{alloc_fn_name}") (param $size i32) (result i32)
                global.get $mem_size

                (global.set $mem_size
                    (i32.add (global.get $mem_size) (local.get $size))
                )
            )
            "#,
            memory_name = WASM_MEMORY_NAME,
            alloc_fn_name = WASM_ALLOC_FN,
            isi_len = isi_hex.len() / 3,
            isi_hex = isi_hex,
        )
    }

    fn encode_hex<T: Encode>(isi: T) -> String {
        let isi_bytes = isi.encode();

        let mut isi_hex = String::with_capacity(3 * isi_bytes.len());
        for (i, c) in hex::encode(isi_bytes).chars().enumerate() {
            if i % 2 == 0 {
                isi_hex.push('\\');
            }

            isi_hex.push(c);
        }

        isi_hex
    }

    #[test]
    fn execute_instruction_exported() -> Result<(), Error> {
        let account_id = AccountId::test("alice", "wonderland");
        let wsv = WorldStateView::new(world_with_test_account(account_id.clone()));

        let isi_hex = {
            let new_account_id = AccountId::test("mad_hatter", "wonderland");
            let register_isi = RegisterBox::new(NewAccount::new(new_account_id));
            encode_hex(Instruction::Register(register_isi))
        };

        let wat = format!(
            r#"
            (module
                ;; Import host function to execute
                (import "iroha" "{execute_fn_name}"
                    (func $exec_fn (param i32 i32))
                )

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param i32 i32)
                    (call $exec_fn (i32.const 0) (i32.const {isi_len}))
                )
            )
            "#,
            main_fn_name = WASM_MAIN_FN_NAME,
            execute_fn_name = EXECUTE_ISI_FN_NAME,
            memory_and_alloc = memory_and_alloc(&isi_hex),
            isi_len = isi_hex.len() / 3,
        );
        let mut runtime = Runtime::new()?;
        assert!(runtime.execute(&wsv, account_id, wat).is_ok());

        Ok(())
    }

    #[test]
    fn execute_query_exported() -> Result<(), Error> {
        let account_id = AccountId::test("alice", "wonderland");
        let wsv = WorldStateView::new(world_with_test_account(account_id.clone()));

        let query_hex = {
            let find_acc_query = FindAccountById::new(account_id.clone());
            encode_hex(QueryBox::FindAccountById(find_acc_query))
        };

        let wat = format!(
            r#"
            (module
                ;; Import host function to execute
                (import "iroha" "{execute_fn_name}"
                    (func $exec_fn (param i32 i32) (result i32 i32))
                )

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param i32 i32)
                    (call $exec_fn (i32.const 0) (i32.const {isi_len}))

                    ;; No use of return values
                    drop drop
                )
            )
            "#,
            main_fn_name = WASM_MAIN_FN_NAME,
            execute_fn_name = EXECUTE_QUERY_FN_NAME,
            memory_and_alloc = memory_and_alloc(&query_hex),
            isi_len = query_hex.len() / 3,
        );

        let mut runtime = Runtime::new()?;
        assert!(runtime.execute(&wsv, account_id, wat).is_ok());

        Ok(())
    }

    #[test]
    fn instruction_limit_reached() -> Result<(), Error> {
        let account_id = AccountId::test("alice", "wonderland");
        let wsv = WorldStateView::new(world_with_test_account(account_id.clone()));

        let isi_hex = {
            let new_account_id = AccountId::test("mad_hatter", "wonderland");
            let register_isi = RegisterBox::new(NewAccount::new(new_account_id));
            encode_hex(Instruction::Register(register_isi))
        };

        let wat = format!(
            r#"
            (module
                ;; Import host function to execute
                (import "iroha" "{execute_fn_name}"
                    (func $exec_fn (param i32 i32))
                )

                {memory_and_alloc}

                ;; Function which starts the smartcontract execution
                (func (export "{main_fn_name}") (param i32 i32)
                    (call $exec_fn (i32.const 0) (i32.const {isi1_end}))
                    (call $exec_fn (i32.const {isi1_end}) (i32.const {isi2_end}))
                )
            )
            "#,
            main_fn_name = WASM_MAIN_FN_NAME,
            execute_fn_name = EXECUTE_ISI_FN_NAME,
            // Store two instructions into adjacent memory and execute them
            memory_and_alloc = memory_and_alloc(&format!("{}{}", isi_hex, isi_hex)),
            isi1_end = isi_hex.len() / 3,
            isi2_end = 2 * isi_hex.len() / 3,
        );
        let mut runtime = Runtime::from_configuration(Configuration {
            fuel_limit: 100_000,
            max_instruction_count: 1,
        })?;
        let res = runtime.execute(&wsv, account_id, wat);

        assert!(res.is_err());
        if let Error::ExportFnCall(trap) = res.unwrap_err() {
            assert_eq!(
                "Number of instructions exceeds maximum(1)",
                trap.display_reason().to_string()
            );
        }

        Ok(())
    }
}