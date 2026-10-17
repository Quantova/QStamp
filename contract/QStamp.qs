// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

contract QStamp {
  entry stamp(hi: u128, lo: u128, kind: u64) {
    emit Stamped(caller, hi, lo, kind);
  }
  entry stamp_until(hi: u128, lo: u128, kind: u64, until: u64) {
    guard now <= until;
    emit StampedUntil(caller, hi, lo, kind, until);
  }
  event Stamped(sender: Q_Address, hi: u128, lo: u128, kind: u64);
  event StampedUntil(sender: Q_Address, hi: u128, lo: u128, kind: u64, until: u64);
}
