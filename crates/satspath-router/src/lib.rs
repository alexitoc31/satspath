pub mod ark;
pub mod ark_routes;
pub mod bip353_preview;
pub mod bolt12;
pub mod fees;
pub mod handoff;
pub mod key_rotation;
pub mod lightning;
pub mod onchain;
pub mod priority;
pub mod quote_response;
pub mod router;
pub mod scoring;
pub mod silent_payments;
pub mod split_payments;
pub mod urgency;
pub mod wallet_executor;

pub use ark::{
    first_ark_method, is_ark_available, verify_ark_vtxo_dag, ArkAspInfo, ArkBoardingHandoff,
    ArkClient, ArkFeeSchedule, ArkForfeitHandoff, ArkIntent, ArkNetwork, ArkOorPaymentRequest,
    ArkRegisterIntentRequest, ArkRegisterIntentResponse, ArkRoundSubmissionReceipt,
    ArkSettlementHandoff, ArkSettlementSubmission, ArkSettlementSubmissionResponse,
    ArkSubmitTxRequest, ArkSubmitTxResponse, ArkVtxoTreeNode, LiveArkAspClient, MockArkClient,
    SimulatedArkIntent,
};
#[cfg(test)]
mod lightning_tests;
pub use ark_routes::{plan_ark_route, ArkRoutePlan, SenderCapabilities};
pub use bip353_preview::quote_from_bip353_resolution;
pub use bolt12::{
    bolt12_merkle_branch, bolt12_signature_digest, bolt12_tagged_hash,
    build_invoice_request_onion_envelope, compute_bolt12_merkle_root, decode_bolt12_bech32,
    encode_bolt12_bech32_checksumless, fetch_bolt12_invoice_via_transport,
    normalize_bolt12_bech32_str, parse_bolt12_offer, resolve_offer_onion_route,
    sign_bolt12_tlv_stream, verify_bolt12_tlv_signature, Bolt12Invoice, Bolt12InvoiceRequest,
    Bolt12Offer, Bolt12Signer, IntroductionNode, OnionMessageEnvelope, OnionMessageTransport,
    ReferenceNodeOnionTransport, ResolvedOnionRoute,
};
pub use fees::{
    compute_median_fee, decay_estimate, fallback_fees, fetch_fee_estimate,
    fetch_fee_estimate_with_config, ConsensusFeeReport, EsploraFeeEstimate, FeeEstimate,
    FeeEstimatorConfig, FeeSource, MempoolFeeEstimate, MultiSourceFeeEstimator,
};
pub use key_rotation::{
    apply_key_rotation, get_effective_identity_pubkey, is_rotation_valid, rotate_identity_key,
    verify_key_rotation,
};
pub use lightning::{
    fetch_invoice, fetch_lnurl_metadata, is_lightning_available_for_amount_sync,
    validate_bolt11_invoice, validate_bolt11_invoice_for_network, LnurlPayMetadata,
    ValidatedInvoice,
};
pub use priority::{select_priority_route, PriorityDecision};
pub use quote_response::{
    build_qr_payload, quote, quote_verified_profile, quote_with_resolver, QuoteRecipient,
    QuoteResponse,
};
pub use router::{
    select_route, select_route_with_fees, FeeRateSnapshot, RouteQuote, RouteRequest, SwapDirective,
};
pub use satspath_core::SplitPaymentRequest;
pub use scoring::{
    score_routes, FeeSnapshot, PaymentRail, RouteCandidate, RouteDecision, RoutePreferences,
};
pub use silent_payments::{
    bip352_input_context, compute_input_hash, create_bip352_outputs, create_silent_payment_address,
    create_silent_payment_address_for_network, extract_bip352_input_pubkey, find_smallest_outpoint,
    parse_outpoint_to_bytes, parse_silent_payment_address, parse_silent_payment_scan_key,
    scan_bip352_transaction, tagged_hash, Bip352DetectedOutput, Bip352InputContext,
    Bip352PrevoutInput, Bip352ReceiveResult, Bip352ScanKeys, Bip352SendResult,
    SilentPaymentAddress, SilentPaymentScanKey, BIP0352_MAX_K, BIP0352_NUMS_H, BIP0352_TAG_INPUTS,
    BIP0352_TAG_LABEL, BIP0352_TAG_SHARED_SECRET,
};
pub use split_payments::{
    calculate_split_amounts, route_split_payment, validate_split_request, SplitPaymentRoute,
    SplitPaymentRoutingRequest, SplitPaymentRoutingResult,
};
pub use urgency::PaymentUrgency;
pub use wallet_executor::{
    execute_quote_handoff, prepare_payment_intent, ApprovedPaymentIntent, BdkHostWallet,
    BdkOnchainBridge, BdkUtxoDescriptor, BoltzHostSignerBroadcaster, BoltzSwapEvidence,
    BoltzTestnetSwapBridge, HandoffExecutionReceipt, HandoffTransparencyEvidence, HandoffTrust,
    HostWalletSdkBridge, IntentVerification, LdkHostNode, LdkLightningBridge, PaymentIntent,
};
