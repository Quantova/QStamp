contract QStamp {
  entry stamp(hi: u128, lo: u128, kind: u64) {
    emit Stamped(caller, hi, lo, kind);
  }
  event Stamped(sender: Q_Address, hi: u128, lo: u128, kind: u64);
}
