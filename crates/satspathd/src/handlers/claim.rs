//! Claim handlers: inspect invite, claim invite, list invites, list notifications.

use anyhow::Result;
use satspath_core::crypto::verify_message_signature;
use satspath_core::privacy::identifier_hash;
use satspath_core::profile::{ClaimNotification, InviteRecord, InviteStatus};
use satspath_core::InviteStore;

use crate::config::AppState;
use crate::handlers::profile::{apply_method_updates, sign_and_store};
use crate::handlers::wallet::{load_or_create_identity, save_wallet};
use crate::types::{ClaimRequest, ClaimResponse, InspectInviteResponse, ProfileUpdateRequest};

pub(crate) fn inspect_invite_handler(
    state: &AppState,
    invite_id: &str,
) -> Result<InspectInviteResponse> {
    let store = InviteStore::open(&state.home)?;
    let invite = store
        .get(invite_id)
        .ok_or_else(|| anyhow::anyhow!("invite '{}' not found", invite_id))?;

    let now = chrono::Utc::now().timestamp();
    let is_expired = now >= invite.expires_at || invite.status == InviteStatus::Expired;
    let is_claimable = !is_expired
        && invite.status != InviteStatus::ClaimedWithPublicProfile
        && invite.status != InviteStatus::Cancelled;

    let sender_verified =
        if let (Some(sig), Some(pubkey)) = (&invite.sender_signature, &invite.sender_pubkey) {
            let message = format!(
                "SatsPath Invite v1\nalias_hash={}\namount_sats={}\ncreated_at={}\nexpires_at={}",
                invite.identifier_hash, invite.amount_sats, invite.created_at, invite.expires_at
            );
            verify_message_signature(&message, sig, pubkey).unwrap_or(false)
        } else {
            false
        };

    Ok(InspectInviteResponse {
        invite_id: invite.invite_id,
        identifier_hash: invite.identifier_hash,
        display_hint: invite.display_hint,
        amount_sats: invite.amount_sats,
        memo: invite.memo,
        status: invite.status,
        is_expired,
        is_claimable,
        created_at: invite.created_at,
        expires_at: invite.expires_at,
        sender_verified,
        sender_pubkey: invite.sender_pubkey,
    })
}

pub(crate) fn claim_invite_handler(state: &AppState, body: ClaimRequest) -> Result<ClaimResponse> {
    if body.invite_id.trim().is_empty() {
        anyhow::bail!("missing invite_id");
    }
    if body.alias.trim().is_empty() {
        anyhow::bail!("missing alias");
    }

    let mut store = InviteStore::open(&state.home)?;
    let invite = store
        .get(&body.invite_id)
        .ok_or_else(|| anyhow::anyhow!("invite '{}' not found", body.invite_id))?;

    let expected_hash = identifier_hash(&body.alias);
    if invite.identifier_hash != expected_hash {
        anyhow::bail!(
            "alias '{}' does not match invite recipient identifier",
            body.alias
        );
    }

    let now = chrono::Utc::now().timestamp();
    if now >= invite.expires_at || invite.status == InviteStatus::Expired {
        anyhow::bail!("invite has expired");
    }

    if invite.status == InviteStatus::ClaimedWithPublicProfile {
        anyhow::bail!("invite has already been claimed");
    }

    if invite.status == InviteStatus::Cancelled {
        anyhow::bail!("invite has been cancelled");
    }

    // Verify sender signature if present
    if let (Some(sig), Some(pubkey)) = (&invite.sender_signature, &invite.sender_pubkey) {
        let message = format!(
            "SatsPath Invite v1\nalias_hash={}\namount_sats={}\ncreated_at={}\nexpires_at={}",
            invite.identifier_hash, invite.amount_sats, invite.created_at, invite.expires_at
        );
        if !verify_message_signature(&message, sig, pubkey)? {
            anyhow::bail!("invalid sender signature on invite");
        }
    }

    // Determine receiver public key and publish profile to transparency log
    let receiver_pubkey = if let Some(signed) = body.signed_profile {
        // Validate signed profile
        if !satspath_core::crypto::verify_signed_profile(&signed)? {
            anyhow::bail!("receiver signed profile verification failed");
        }
        if signed.profile.alias != body.alias {
            anyhow::bail!("signed profile alias does not match claim alias");
        }
        if signed.profile.methods.is_empty() {
            anyhow::bail!("signed profile must contain at least one payment method");
        }
        let pubkey = signed.profile.identity_pubkey.clone();

        // Commit to transparency log
        let tstore = satspath_core::TransactionalTransparencyStore::open(&state.home)?;
        let log = tstore.load_log()?;
        let history: Vec<_> = log.history(&expected_hash).into_iter().cloned().collect();
        let previous_event_hash = history.last().map(|e| e.event_hash()).transpose()?;
        let next_sequence = satspath_core::next_identifier_sequence(None, &history)?;

        let event = satspath_core::NameEvent {
            version: 1,
            identifier_hash: expected_hash.clone(),
            action: if history.is_empty() {
                satspath_core::NameAction::Register
            } else {
                satspath_core::NameAction::UpdateProfile
            },
            identity_pubkey: pubkey.clone(),
            profile_hash: satspath_core::transparency::profile_hash(&signed)?,
            sequence: next_sequence,
            previous_event_hash,
            created_at: now,
            identifier_attestation_hash: None,
            removed_method_hashes: vec![],
            rotation: signed.profile.rotation.clone(),
            recovery_policy: signed.profile.recovery_policy.clone(),
            recovery: signed.profile.recovery.clone(),
            owner_signature: signed.signature.clone(),
        };

        let candidate = log.prepare_append(event.clone(), &signed)?;
        let operator =
            crate::handlers::transparency::load_or_create_transparency_operator(&state.home)?;
        let checkpoint = candidate.prepare_checkpoint(&operator)?;
        tstore.commit_profile_event_checkpoint(&body.alias, &signed, &event, &checkpoint)?;
        pubkey
    } else {
        // Build and publish profile using daemon identity
        let mut wallet = load_or_create_identity(&state.home)?;
        wallet.alias = Some(body.alias.clone());

        let update_req = ProfileUpdateRequest {
            alias: Some(body.alias.clone()),
            lightning_address: body.lightning_address,
            onchain_address: body.onchain_address,
            onchain_pubkey: body.onchain_pubkey,
            ark_server: body.ark_server,
            ark_pubkey: body.ark_pubkey,
            remove_methods: vec![],
            recovery_policy: None,
        };

        apply_method_updates(&mut wallet, &state.network, update_req, false)?;
        sign_and_store(&state.home, &mut wallet, &state.network)?;
        save_wallet(&state.home, &wallet)?;
        wallet.identity_pubkey.unwrap_or_default()
    };

    // Transition invite to ClaimedWithPublicProfile and create notification
    store.claim(&body.invite_id, &receiver_pubkey)?;

    Ok(ClaimResponse {
        status: "claimed".into(),
        invite_id: body.invite_id,
        alias: body.alias,
        amount_sats: invite.amount_sats,
        profile_pubkey: receiver_pubkey,
        claimed_at: now,
        message: "Invite successfully claimed and receiver profile published to transparency log"
            .into(),
    })
}

pub(crate) fn list_invites_handler(state: &AppState) -> Result<Vec<InviteRecord>> {
    let mut store = InviteStore::open(&state.home)?;
    store.list()
}

pub(crate) fn list_notifications_handler(state: &AppState) -> Result<Vec<ClaimNotification>> {
    let store = InviteStore::open(&state.home)?;
    Ok(store.notifications().to_vec())
}

pub(crate) fn mark_notification_read_handler(
    state: &AppState,
    notification_id: &str,
) -> Result<serde_json::Value> {
    let mut store = InviteStore::open(&state.home)?;
    store.mark_notification_read(notification_id)?;
    Ok(serde_json::json!({
        "status": "ok",
        "notification_id": notification_id,
        "read": true
    }))
}

pub(crate) fn mark_all_notifications_read_handler(state: &AppState) -> Result<serde_json::Value> {
    let mut store = InviteStore::open(&state.home)?;
    store.mark_all_notifications_read()?;
    Ok(serde_json::json!({
        "status": "ok",
        "all_read": true
    }))
}
