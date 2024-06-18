use reth::primitives::IntoRecoveredTransaction;
use reth::{api::FullNodeComponents, transaction_pool::TransactionPool};
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_ethereum::EthereumNode;
use reth_revm::primitives::{EVMError, InvalidTransaction, ResultAndState};
use reth_tracing::tracing::info;
use txpool_exex::simulation::reth_runner_builder;

use std::sync::Arc;
use std::time::Instant;

const BLOCK_TIME: u64 = 12;

async fn txpool_exex<Node: FullNodeComponents>(mut ctx: ExExContext<Node>) -> eyre::Result<()> {
    while let Some(notification) = ctx.notifications.recv().await {
        match &notification {
            ExExNotification::ChainCommitted { new } => {
                info!(committed_chain = ?new.range(), "Received commit");
            }
            ExExNotification::ChainReorged { old, new } => {
                info!(from_chain = ?old.range(), to_chain = ?new.range(), "Received reorg");
            }
            ExExNotification::ChainReverted { old } => {
                info!(reverted_chain = ?old.range(), "Received revert");
            }
        };

        if let Some(committed_chain) = notification.committed_chain() {
            let tx_pool = ctx.components.pool();
            let mut best_txs = tx_pool.best_transactions();

            let reth_runner = Arc::new(reth_runner_builder()?);

            while let Some(pool_tx) = best_txs.next() {
                let now = Instant::now();
                let tx_age = now.duration_since(pool_tx.timestamp).as_secs();
                if tx_age < BLOCK_TIME {
                    continue;
                }

                // convert tx to a signed transaction
                let tx = pool_tx.to_recovered_transaction();

                let ResultAndState { result, state: _ } = match reth_runner
                    .validate_tx(&tx, tx.recover_signer().expect("could not recover signer"))
                {
                    Ok(res) => res,
                    Err(err) => {
                        match err {
                            EVMError::Transaction(err) => {
                                if matches!(err, InvalidTransaction::NonceTooLow { .. }) {
                                    // if the nonce is too low, we can skip this transaction
                                    println!("skipping nonce too low transaction");
                                } else {
                                    // if the transaction is invalid, we can skip it and all of its
                                    // descendants
                                    println!("skipping invalid transaction and its descendants");
                                    best_txs.mark_invalid(&pool_tx);
                                }

                                continue;
                            }
                            err => {
                                // this is an error that we should treat as fatal for this attempt
                                println!("Reth simulator error: {:?}", err);
                                continue;
                            }
                        }
                    }
                };

                ctx.events
                    .send(ExExEvent::FinishedHeight(committed_chain.tip().number))?;

                println!(
                    "Transaction {:?}: used gas {}, success: {}",
                    tx.hash,
                    result.gas_used(),
                    result.is_success()
                );
            }
        }
    }

    Ok(())
}

fn main() -> eyre::Result<()> {
    reth::cli::Cli::parse_args().run(|builder, _| async move {
        let handle = builder
            .node(EthereumNode::default())
            .install_exex("txpool_exex", |ctx| async move { Ok(txpool_exex(ctx)) })
            .launch()
            .await?;

        handle.wait_for_node_exit().await
    })
}
