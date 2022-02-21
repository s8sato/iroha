//! Routing functions for Torii. If you want to add an endpoint to
//! Iroha you should add it here by creating a `handle_*` function,
//! and add it to impl Torii.
use super::*;

#[iroha_futures::telemetry_future]
pub(crate) async fn handle_instructions<W: WorldTrait>(
    iroha_cfg: Configuration,
    queue: Arc<Queue<W>>,
    transaction: VersionedTransaction,
) -> Result<Empty> {
    let transaction: Transaction = transaction.into_v1();
    let transaction = VersionedAcceptedTransaction::from_transaction(
        transaction,
        &iroha_cfg.sumeragi.transaction_limits,
    )
    .map_err(Error::AcceptTransaction)?;
    #[allow(clippy::map_err_ignore)]
    let push_result = queue.push(transaction).map_err(|(_, err)| err);
    if let Err(ref error) = push_result {
        iroha_logger::warn!(%error, "Failed to push to queue")
    }
    push_result
        .map_err(Box::new)
        .map_err(Error::PushIntoQueue)
        .map(|()| Empty)
}

#[iroha_futures::telemetry_future]
pub(crate) async fn handle_queries<W: WorldTrait>(
    wsv: Arc<WorldStateView<W>>,
    query_validator: Arc<IsQueryAllowedBoxed<W>>,
    pagination: Pagination,
    request: VerifiedQueryRequest,
) -> Result<Scale<VersionedQueryResult>, query::Error> {
    let valid_request = request.validate(&wsv, &query_validator)?;
    let result = valid_request.execute(&wsv)?;
    let result = QueryResult(if let Value::Vec(value) = result {
        Value::Vec(value.into_iter().paginate(pagination).collect())
    } else {
        result
    });
    Ok(Scale(result.into()))
}

#[derive(Serialize)]
#[non_exhaustive]
enum Health {
    Healthy,
}

#[iroha_futures::telemetry_future]
async fn handle_health() -> Json {
    reply::json(&Health::Healthy)
}

#[iroha_futures::telemetry_future]
async fn handle_pending_transactions<W: WorldTrait>(
    queue: Arc<Queue<W>>,
    pagination: Pagination,
) -> Result<Scale<VersionedPendingTransactions>> {
    Ok(Scale(
        queue
            .all_transactions()
            .into_iter()
            .map(VersionedAcceptedTransaction::into_v1)
            .map(Transaction::from)
            .paginate(pagination)
            .collect(),
    ))
}

#[iroha_futures::telemetry_future]
async fn handle_get_configuration(
    iroha_cfg: Configuration,
    get_cfg: GetConfiguration,
) -> Result<Json> {
    use GetConfiguration::*;

    match get_cfg {
        Docs(field) => {
            Configuration::get_doc_recursive(field.iter().map(AsRef::as_ref).collect::<Vec<&str>>())
                .wrap_err("Failed to get docs {:?field}")
                .and_then(|doc| {
                    Context::wrap_err(serde_json::to_value(doc), "Failed to serialize docs")
                })
        }
        Value => serde_json::to_value(iroha_cfg).wrap_err("Failed to serialize value"),
    }
    .map(|v| reply::json(&v))
    .map_err(Error::Config)
}

#[iroha_futures::telemetry_future]
async fn handle_post_configuration(
    iroha_cfg: Configuration,
    cfg: PostConfiguration,
) -> Result<Json> {
    use iroha_config::runtime_upgrades::Reload;
    use PostConfiguration::*;

    iroha_logger::debug!(?cfg);
    match cfg {
        // TODO: Now the configuration value and the actual value don't match.
        LogLevel(level) => {
            iroha_cfg.logger.max_log_level.reload(level.into())?;
        }
    };

    Ok(reply::json(&true))
}

#[iroha_futures::telemetry_future]
async fn handle_blocks_stream<W: WorldTrait>(
    wsv: &WorldStateView<W>,
    mut stream: WebSocket,
) -> eyre::Result<()> {
    let subscription_request: VersionedBlockSubscriberMessage = stream.recv().await?;
    let mut from_height = subscription_request.into_v1().try_into()?;

    stream
        .send(VersionedBlockPublisherMessage::from(
            BlockPublisherMessage::SubscriptionAccepted,
        ))
        .await?;

    let mut rx = wsv.subscribe_to_new_block_notifications();
    stream_blocks(&mut from_height, wsv, &mut stream).await?;

    loop {
        rx.changed().await?;
        stream_blocks(&mut from_height, wsv, &mut stream).await?;
    }
}

async fn stream_blocks<W: WorldTrait>(
    from_height: &mut u64,
    wsv: &WorldStateView<W>,
    stream: &mut WebSocket,
) -> eyre::Result<()> {
    #[allow(clippy::expect_used)]
    for block in wsv.blocks_from_height(
        (*from_height)
            .try_into()
            .expect("Blockchain size limit reached"),
    ) {
        stream
            .send(VersionedBlockPublisherMessage::from(
                BlockPublisherMessage::from(block),
            ))
            .await?;

        let message: VersionedBlockSubscriberMessage = stream.recv().await?;
        if let BlockSubscriberMessage::BlockReceived = message.into_v1() {
            *from_height += 1;
        } else {
            return Err(eyre!("Expected `BlockReceived` message"));
        }
    }

    Ok(())
}

mod subscription {
    //! This module contains `handle_subscription()` function and other stuff for its implementation

    use super::*;
    use crate::event;

    /// Type for any error during subscription handling
    #[derive(thiserror::Error, Debug)]
    enum Error {
        /// Event consuming error
        #[error("Event consuming error: {0}")]
        Consumer(Box<event::Error>),
        /// Event receiving error
        #[error("Event receiving error: {0}")]
        Event(#[from] tokio::sync::broadcast::error::RecvError),
        /// Error from provided websocket
        #[error("WebSocket error: {0}")]
        WebSocket(#[from] warp::Error),
        /// Error, indicating that `Close` message was received
        #[error("`Close` message received")]
        CloseMessage,
    }

    impl From<event::Error> for Error {
        fn from(error: event::Error) -> Self {
            match error {
                event::Error::Stream(box_err)
                    if matches!(*box_err, event::StreamError::CloseMessage) =>
                {
                    Self::CloseMessage
                }
                error => Self::Consumer(Box::new(error)),
            }
        }
    }

    type Result<T> = core::result::Result<T, Error>;

    /// Handle subscription request
    ///
    /// Subscribes `stream` for `events` filtered by filter that is received through the `stream`
    ///
    /// There should be a [`warp::filters::ws::Message::close()`] message to end subscription
    #[iroha_futures::telemetry_future]
    pub async fn handle_subscription(events: EventsSender, stream: WebSocket) -> eyre::Result<()> {
        match subscribe_forever(events, stream).await {
            Ok(()) | Err(Error::CloseMessage) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Make endless `stream` subscription for `events`
    ///
    /// Ideally should return `Result<!>` cause it either runs forever either returns `Err` variant
    async fn subscribe_forever(events: EventsSender, stream: WebSocket) -> Result<()> {
        let mut events = events.subscribe();
        let mut consumer = Consumer::new(stream).await?;

        loop {
            tokio::select! {
                // This branch catches `Close` ans unexpected messages
                closed = consumer.stream_closed() => {
                    match closed {
                        Ok(()) => return Err(Error::CloseMessage),
                        Err(err) => return Err(err.into())
                    }
                }
                // This branch catches and sends events
                event = events.recv() => {
                    let event = event?;
                    iroha_logger::trace!(?event);
                    consumer.consume(event).await?;
                }
                // Else branch to prevent panic
                else => ()
            }
        }
    }
}

async fn handle_metrics<W: WorldTrait>(
    wsv: Arc<WorldStateView<W>>,
    network: Addr<IrohaNetwork>,
) -> Result<String> {
    update_metrics(&wsv, network).await?;
    wsv.metrics.try_to_string().map_err(Error::Prometheus)
}

async fn handle_status<W: WorldTrait>(
    wsv: Arc<WorldStateView<W>>,
    network: Addr<IrohaNetwork>,
) -> Result<Json> {
    update_metrics(&wsv, network).await?;
    let status = Status::from(&wsv.metrics);
    Ok(reply::json(&status))
}

async fn update_metrics<W: WorldTrait>(
    wsv: &WorldStateView<W>,
    network: Addr<IrohaNetwork>,
) -> Result<()> {
    let peers = network
        .send(iroha_p2p::network::GetConnectedPeers)
        .await
        .map_err(Error::Status)?
        .peers
        .len() as u64;
    #[allow(clippy::cast_possible_truncation)]
    if let Some(timestamp) = wsv.genesis_timestamp() {
        // this will overflow in 584942417years.
        wsv.metrics
            .uptime_since_genesis_ms
            .set((current_time().as_millis() - timestamp) as u64)
    };
    let domains = wsv.domains();
    wsv.metrics.domains.set(domains.len() as u64);
    wsv.metrics.connected_peers.set(peers);
    for domain in domains {
        wsv.metrics
            .accounts
            .get_metric_with_label_values(&[domain.id.name.as_ref()])
            .wrap_err("Failed to compose domains")
            .map_err(Error::Prometheus)?
            .set(domain.accounts.values().len() as u64);
    }
    Ok(())
}

/// Convert accumulated `Rejection` into appropriate `Reply`.
#[allow(clippy::unused_async)]
// TODO: -> Result<impl Reply, Infallible>
pub(crate) async fn handle_rejection(rejection: Rejection) -> Result<Response, Rejection> {
    use super::Error::*;

    let err = if let Some(err) = rejection.find::<Error>() {
        err
    } else {
        iroha_logger::error!(?rejection, "unhandled rejection");
        return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };

    #[allow(clippy::match_same_arms)]
    let response = match err {
        Query(err) => err.clone().into_response(),
        VersionedTransaction(err) => {
            reply::with_status(err.to_string(), err.status_code()).into_response()
        }
        AcceptTransaction(_err) => return unhandled(rejection),
        RequestPendingTransactions(_err) => return unhandled(rejection),
        DecodeRequestPendingTransactions(err) => {
            reply::with_status(err.to_string(), err.status_code()).into_response()
        }
        EncodePendingTransactions(err) => {
            reply::with_status(err.to_string(), err.status_code()).into_response()
        }
        TxTooBig => return unhandled(rejection),
        Config(_err) => return unhandled(rejection),
        PushIntoQueue(_err) => return unhandled(rejection),
        Status(_err) => return unhandled(rejection),
        ConfigurationReload(_err) => return unhandled(rejection),
        Prometheus(_err) => return unhandled(rejection),
    };

    Ok(response)
}

// TODO: Remove this. Handle all the `Error` cases in `handle_rejection`
fn unhandled(rejection: Rejection) -> Result<Response, Rejection> {
    iroha_logger::error!(?rejection, "unhandled rejection");
    Err(rejection)
}

impl<W: WorldTrait> Torii<W> {
    /// Construct `Torii` from `ToriiConfiguration`.
    pub fn from_configuration(
        iroha_cfg: Configuration,
        wsv: Arc<WorldStateView<W>>,
        queue: Arc<Queue<W>>,
        query_validator: Arc<IsQueryAllowedBoxed<W>>,
        events: EventsSender,
        network: Addr<IrohaNetwork>,
    ) -> Self {
        Self {
            iroha_cfg,
            wsv,
            events,
            query_validator,
            queue,
            network,
        }
    }

    /// Helper function to create router. This router can tested without starting up an HTTP server
    fn create_telemetry_router(&self) -> impl Filter<Extract = impl warp::Reply> + Clone + Send {
        let get_router_status = endpoint2(
            handle_status,
            warp::path(uri::STATUS).and(add_state!(self.wsv, self.network)),
        );
        let get_router_metrics = endpoint2(
            handle_metrics,
            warp::path(uri::METRICS).and(add_state!(self.wsv, self.network)),
        );

        warp::get()
            .and(get_router_status)
            .or(get_router_metrics)
            .with(warp::trace::request())
            .recover(handle_rejection)
    }

    /// Helper function to create router. This router can tested without starting up an HTTP server
    pub(crate) fn create_api_router(
        &self,
    ) -> impl Filter<Extract = impl warp::Reply> + Clone + Send {
        let get_router = warp::path(uri::HEALTH)
            .and_then(|| async { Ok::<_, Infallible>(handle_health().await) })
            .or(endpoint2(
                handle_pending_transactions,
                warp::path(uri::PENDING_TRANSACTIONS)
                    .and(add_state!(self.queue))
                    .and(paginate()),
            ))
            .or(endpoint2(
                handle_get_configuration,
                warp::path(uri::CONFIGURATION)
                    .and(add_state!(self.iroha_cfg))
                    .and(warp::body::json()),
            ));

        let post_router = endpoint3(
            handle_instructions,
            warp::path(uri::TRANSACTION)
                .and(add_state!(self.iroha_cfg, self.queue))
                .and(warp::body::content_length_limit(
                    self.iroha_cfg.torii.max_content_len as u64,
                ))
                .and(body::versioned()),
        )
        .or(endpoint4(
            handle_queries,
            warp::path(uri::QUERY)
                .and(add_state!(self.wsv, self.query_validator))
                .and(paginate())
                .and(body::query()),
        ))
        .or(endpoint2(
            handle_post_configuration,
            warp::path(uri::CONFIGURATION)
                .and(add_state!(self.iroha_cfg))
                .and(warp::body::json()),
        ));

        let events_ws_router = warp::path(uri::SUBSCRIPTION)
            .and(add_state!(self.events))
            .and(warp::ws())
            .map(|events, ws: Ws| {
                ws.on_upgrade(|this_ws| async move {
                    if let Err(error) = subscription::handle_subscription(events, this_ws).await {
                        iroha_logger::error!(%error, "Failed to subscribe someone");
                    }
                })
            });

        // `warp` panics if there is `/` in the string given to the `warp::path` filter
        // Path filter has to be boxed to have a single uniform type during iteration
        let block_ws_router_path = uri::BLOCKS_STREAM
            .split('/')
            .skip_while(|p| p.is_empty())
            .fold(warp::any().boxed(), |path_filter, path| {
                path_filter.and(warp::path(path)).boxed()
            });

        let blocks_ws_router = block_ws_router_path
            .and(add_state!(self.wsv))
            .and(warp::ws())
            .map(|wsv: Arc<_>, ws: Ws| {
                ws.on_upgrade(|this_ws| async move {
                    if let Err(error) = handle_blocks_stream(&wsv, this_ws).await {
                        iroha_logger::error!(%error, "Failed to subscribe to blocks stream");
                    }
                })
            });

        let ws_router = events_ws_router.or(blocks_ws_router);

        ws_router
            .or(warp::post().and(post_router))
            .or(warp::get().and(get_router))
            .with(warp::trace::request())
            .recover(handle_rejection)
    }

    /// Start status and metrics endpoints.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    fn start_telemetry(self: Arc<Self>) -> eyre::Result<Vec<tokio::task::JoinHandle<()>>> {
        let telemetry_url = &self.iroha_cfg.torii.telemetry_url;

        let mut handles = vec![];
        match telemetry_url.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    let torii = Arc::clone(&self);

                    handles.push(tokio::spawn(async move {
                        let telemetry_router = torii.create_telemetry_router();
                        warp::serve(telemetry_router).run(addr).await;
                    }));
                }

                Ok(handles)
            }
            Err(error) => {
                iroha_logger::error!(%telemetry_url, %error, "Telemetry address configuration parse error");
                Err(eyre::Error::new(error))
            }
        }
    }

    /// Start main api endpoints.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    fn start_api(self: Arc<Self>) -> eyre::Result<Vec<tokio::task::JoinHandle<()>>> {
        let api_url = &self.iroha_cfg.torii.api_url;

        let mut handles = vec![];
        match api_url.to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    let torii = Arc::clone(&self);

                    handles.push(tokio::spawn(async move {
                        let api_router = torii.create_api_router();
                        warp::serve(api_router).run(addr).await;
                    }));
                }

                Ok(handles)
            }
            Err(error) => {
                iroha_logger::error!(%api_url, %error, "API address configuration parse error");
                Err(eyre::Error::new(error))
            }
        }
    }

    /// To handle incoming requests `Torii` should be started first.
    ///
    /// # Errors
    /// Can fail due to listening to network or if http server fails
    #[iroha_futures::telemetry_future]
    pub async fn start(self) -> eyre::Result<()> {
        let mut handles = vec![];

        let torii = Arc::new(self);
        handles.extend(Arc::clone(&torii).start_telemetry()?);
        handles.extend(Arc::clone(&torii).start_api()?);

        handles
            .into_iter()
            .collect::<FuturesUnordered<_>>()
            .for_each(|handle| {
                if let Err(error) = handle {
                    iroha_logger::error!(%error, "Join handle error");
                }

                futures::future::ready(())
            })
            .await;

        Ok(())
    }
}
