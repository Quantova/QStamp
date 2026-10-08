contract QStamp {
  // Records a 32 byte commitment and a record kind on chain, together with the account that signed the transaction.
  entry stamp(hi: u128, lo: u128, kind: u64) {
    emit Stamped(caller, hi, lo, kind);
  }
  event Stamped(sender: Q_Address, hi: u128, lo: u128, kind: u64);
}
