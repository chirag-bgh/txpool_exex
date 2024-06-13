use reth::api::ConfigureEvm;
use reth::providers::ProviderFactory;
use reth::{
    beacon_consensus::EthBeaconConsensus,
    blockchain_tree::{
        BlockchainTree, BlockchainTreeConfig, ShareableBlockchainTree, TreeExternals,
    },
    primitives::{Address, TransactionSigned},
};
use reth_db::{database::Database, open_db_read_only};
use reth_evm_ethereum::{execute::EthExecutorProvider, EthEvmConfig};
use reth_primitives::{
    revm::env::{fill_block_env, fill_tx_env},
    revm_primitives::EVMError,
    ChainSpec, ChainSpecBuilder,
};
use reth_provider::providers::StaticFileProvider;
use reth_provider::{providers::BlockchainProvider, BlockReaderIdExt, StateProviderFactory};
use reth_revm::primitives::InvalidTransaction::InvalidChainId;
use reth_revm::{database::StateProviderDatabase, db::CacheDB, primitives::ResultAndState};

use std::path::Path;
use std::sync::Arc;

pub fn reth_runner_builder() -> eyre::Result<RethRunner<Arc<reth_db::mdbx::DatabaseEnv>>> {
    let path = std::env::var("RETH_DB_PATH")?;
    let db_path = Path::new(&path);
    let db = Arc::new(open_db_read_only(db_path, Default::default())?);

    let chain_spec = Arc::new(ChainSpecBuilder::mainnet().build());
    let factory = ProviderFactory::new(
        db.clone(),
        chain_spec.clone(),
        StaticFileProvider::read_only(db_path.join("static_files"))?,
    );

    let provider = Arc::new({
        let consensus = Arc::new(EthBeaconConsensus::new(chain_spec.clone()));
        let executor = EthExecutorProvider::ethereum(chain_spec.clone());

        let tree_externals = TreeExternals::new(factory.clone(), consensus, executor);
        let tree = BlockchainTree::new(tree_externals, BlockchainTreeConfig::default(), None)?;
        let blockchain_tree = Arc::new(ShareableBlockchainTree::new(tree));

        BlockchainProvider::new(factory, blockchain_tree)?
    });

    Ok(RethRunner::new(chain_spec, provider))
}

pub struct RethRunner<DB> {
    pub spec: Arc<ChainSpec>,
    pub provider: Arc<BlockchainProvider<DB>>,
}

impl<DB> RethRunner<DB> {
    pub fn new(spec: Arc<ChainSpec>, provider: Arc<BlockchainProvider<DB>>) -> Self {
        Self { spec, provider }
    }
}

impl<DB> RethRunner<DB>
where
    DB: Database,
{
    pub fn validate_tx(
        &self,
        tx: &TransactionSigned,
        sender: Address,
    ) -> Result<ResultAndState, EVMError<String>> {
        if tx.chain_id().is_none() || tx.chain_id().unwrap() != self.spec.chain().id() {
            return Err(EVMError::Transaction(InvalidChainId));
        }
        if tx.is_eip1559() || tx.is_eip4844() && tx.max_priority_fee_per_gas().unwrap() == 0 {
            return Err(EVMError::Custom("Priority fee is 0".to_string()));
        }

        let latest_block_header = self
            .provider
            .latest_header()
            .map_err(|_e| EVMError::Database(String::from("Error fetching latest sealed header")))?
            .unwrap();

        let latest_state = self
            .provider
            .state_by_block_hash(latest_block_header.hash())
            .map_err(|_| EVMError::Database(String::from("Error fetching latest state")))?;

        let state = Arc::new(StateProviderDatabase::new(latest_state));
        let db = CacheDB::new(Arc::clone(&state));
        let evm_config = EthEvmConfig::default();
        let mut evm = evm_config.evm(db);
        fill_block_env(evm.block_mut(), &self.spec, &latest_block_header, true);
        fill_tx_env(evm.tx_mut(), tx, sender);

        evm.transact()
            .map_err(|_| EVMError::Database(String::from("Error executing transaction")))
    }
}
