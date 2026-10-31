//! Reads {"txs":[{"hex": "...", "rings": [[["key","mask"], ...], ...]}]} on stdin and,
//! for each transaction, reports what monero-oxide computes: whether it parses and
//! re-serializes identically, its hash, signature hash and weight, and whether every
//! CLSAG and the Bulletproof(+) verify.
use std::io::Read;

use monero_oxide::{
  ed25519::CompressedPoint,
  ringct::RctPrunable,
  transaction::{Input, Transaction},
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Req {
  txs: Vec<TxReq>,
}

#[derive(Deserialize)]
struct TxReq {
  hex: String,
  rings: Vec<Vec<[String; 2]>>,
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

fn point(s: &str) -> Result<CompressedPoint, String> {
  let b = hex::decode(s).map_err(|e| e.to_string())?;
  let a: [u8; 32] = b.try_into().map_err(|_| "point is not 32 bytes".to_string())?;
  Ok(CompressedPoint::from(a))
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

fn main() {
  let mut input = String::new();
  std::io::stdin().read_to_string(&mut input).expect("read stdin");
  let req: Req = serde_json::from_str(&input).expect("parse request");
  let out: Vec<TxRes> = req
    .txs
    .iter()
    .map(|t| check(t).unwrap_or_else(|e| TxRes { error: e, ..Default::default() }))
    .collect();
  println!("{}", serde_json::to_string(&out).expect("serialize"));
}
