use alloy_network::Ethereum;
use alloy_node_bindings::{Anvil, AnvilInstance};
use alloy_provider::{Provider, RootProvider};
use alloy_pubsub::PubSubFrontend;
use alloy_rpc_client::RpcClient;
use eyre::Result;
use futures_util::StreamExt;
#[tokio::main]
async fn main() -> Result<()> {
    let (provider, _anvil) = init().await;

    let sub = provider.subscribe_blocks().await?;
    let mut stream = sub.into_stream().take(2);
    while let Some(block) = stream.next().await {
        println!("Block: {:?}", block.header.number);
    }
    Ok(())
}

async fn init() -> (RootProvider<Ethereum, PubSubFrontend>, AnvilInstance) {
    let anvil = Anvil::new().block_time(1).spawn();
    let ws = alloy_rpc_client::WsConnect::new(anvil.ws_endpoint());
    let client = RpcClient::connect_pubsub(ws).await.unwrap();
    let provider = RootProvider::<Ethereum, _>::new(client);

    (provider, anvil)
}
