//! Reads a JSON request on stdin and reports what monero-oxide computes:
//!
//! - `txs`: for each {"hex", "rings"}: whether it parses and re-serializes identically,
//!   its hash, signature hash and weight, and whether every CLSAG and the range proof
//!   verify.
//! - `scans`: for each {"tx_hex", "miner_tx_hex", "spend_pub", "view_sec", "subaddresses"}:
//!   the outputs monero-wallet's Scanner finds for that view pair (index, subaddress,
//!   amount, encrypted payment ID), scanning a block made of the miner tx and the tx.
use std::io::Read;

use monero_oxide::{
  block::{Block, BlockHeader},
  ed25519::{CompressedPoint, Scalar},
  ringct::RctPrunable,
  transaction::{Input, Pruned, Transaction},
};
use monero_wallet::{
  address::SubaddressIndex, extra::PaymentId, interface::ScannableBlock, Scanner, ViewPair,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Deserialize)]
struct Req {
  #[serde(default)]
  txs: Vec<TxReq>,
  #[serde(default)]
  scans: Vec<ScanReq>,
}

#[derive(Deserialize)]
struct TxReq {
  hex: String,
  rings: Vec<Vec<[String; 2]>>,
}

#[derive(Deserialize)]
struct ScanReq {
  tx_hex: String,
  miner_tx_hex: String,
  spend_pub: String,
  view_sec: String,
  subaddresses: Vec<[u32; 2]>,
}

#[derive(Serialize, Default)]
struct TxRes {
  parsed: bool,
  reserialized_equal: bool,
  hash: String,
  signature_hash: String,
  weight: usize,
  clsags: Vec<bool>,
  range_proof: bool,
  error: String,
}

#[derive(Serialize)]
struct Found {
  index: u64,
  major: u32,
  minor: u32,
  amount: u64,
  payment_id: String,
}

#[derive(Serialize, Default)]
struct ScanRes {
  outputs: Vec<Found>,
  error: String,
}

#[derive(Serialize)]
struct Res {
  txs: Vec<TxRes>,
  scans: Vec<ScanRes>,
}

fn bytes32(s: &str) -> Result<[u8; 32], String> {
  let b = hex::decode(s).map_err(|e| e.to_string())?;
  b.try_into().map_err(|_| "value is not 32 bytes".to_string())
}

fn point(s: &str) -> Result<CompressedPoint, String> {
  Ok(CompressedPoint::from(bytes32(s)?))
}

fn check(req: &TxReq) -> Result<TxRes, String> {
  let raw = hex::decode(&req.hex).map_err(|e| e.to_string())?;
  let tx = Transaction::read(&mut raw.as_slice()).map_err(|e| format!("read: {e}"))?;
  let mut res = TxRes { parsed: true, ..Default::default() };
  res.reserialized_equal = tx.serialize() == raw;
  res.hash = hex::encode(tx.hash());
  res.weight = tx.weight();
  let Some(sig_hash) = tx.signature_hash() else { return Ok(res) };
  res.signature_hash = hex::encode(sig_hash);
  let Transaction::V2 { prefix, proofs: Some(proofs) } = &tx else { return Ok(res) };
  let RctPrunable::Clsag { clsags, pseudo_outs, bulletproof } = &proofs.prunable else {
    return Err("not a CLSAG transaction".into());
  };
  if req.rings.len() != prefix.inputs.len() {
    return Err("ring count mismatch".into());
  }
  for (i, input) in prefix.inputs.iter().enumerate() {
    let Input::ToKey { key_image, .. } = input else { return Err("non-key input".into()) };
    let ring = req.rings[i]
      .iter()
      .map(|m| Ok([point(&m[0])?, point(&m[1])?]))
      .collect::<Result<Vec<_>, String>>()?;
    res.clsags.push(clsags[i].verify(ring, key_image, &pseudo_outs[i], &sig_hash).is_ok());
  }
  res.range_proof = bulletproof.verify(&mut OsRng, &proofs.base.commitments);
  Ok(res)
}

fn scan(req: &ScanReq) -> Result<ScanRes, String> {
  let read_tx = |h: &str| -> Result<Transaction, String> {
    let raw = hex::decode(h).map_err(|e| e.to_string())?;
    Transaction::read(&mut raw.as_slice()).map_err(|e| format!("read: {e}"))
  };
  let tx = read_tx(&req.tx_hex)?;
  let miner = read_tx(&req.miner_tx_hex)?;
  let header =
    BlockHeader { hardfork_version: 16, hardfork_signal: 16, timestamp: 0, previous: [0; 32], nonce: 0 };
  let block = Block::new(header, miner, vec![tx.hash()]).ok_or("bad block")?;
  let scannable = ScannableBlock {
    block,
    transactions: vec![Transaction::<Pruned>::from(tx)],
    output_index_for_first_ringct_output: Some(0),
  };
  let spend = point(&req.spend_pub)?.decompress().ok_or("bad spend key")?;
  let view = Scalar::read(&mut bytes32(&req.view_sec)?.as_slice()).map_err(|e| e.to_string())?;
  let pair = ViewPair::new(spend, Zeroizing::new(view)).map_err(|e| format!("{e:?}"))?;
  let mut scanner = Scanner::new(pair);
  for [major, minor] in &req.subaddresses {
    if let Some(idx) = SubaddressIndex::new(*major, *minor) {
      scanner.register_subaddress(idx);
    }
  }
  let found = scanner.scan(scannable).map_err(|e| format!("scan: {e:?}"))?;
  let mut res = ScanRes::default();
  for o in found.ignore_additional_timelock() {
    let (major, minor) = o.subaddress().map_or((0, 0), |s| (s.account(), s.address()));
    let payment_id = match o.payment_id() {
      Some(PaymentId::Encrypted(p)) => hex::encode(p),
      Some(PaymentId::Unencrypted(p)) => hex::encode(p),
      None => String::new(),
    };
    res.outputs.push(Found {
      index: o.index_in_transaction(),
      major,
      minor,
      amount: o.commitment().amount,
      payment_id,
    });
  }
  Ok(res)
}

fn main() {
  let mut input = String::new();
  std::io::stdin().read_to_string(&mut input).expect("read stdin");
  let req: Req = serde_json::from_str(&input).expect("parse request");
  let res = Res {
    txs: req
      .txs
      .iter()
      .map(|t| check(t).unwrap_or_else(|e| TxRes { error: e, ..Default::default() }))
      .collect(),
    scans: req
      .scans
      .iter()
      .map(|s| scan(s).unwrap_or_else(|e| ScanRes { error: e, ..Default::default() }))
      .collect(),
  };
  println!("{}", serde_json::to_string(&res).expect("serialize"));
}
