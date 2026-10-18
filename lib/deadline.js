// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const { AsyncLocalStorage } = require('async_hooks');

const MIN_DEADLINE_MS = 100;
const MAX_DEADLINE_MS = 86400000;
const OPEN = Object.freeze({ deadline: Infinity, signal: undefined });
const scope = new AsyncLocalStorage();

function stopError(reason) {
  const e = new Error(reason);
  e.code = 'QSTAMP_TRANSPORT';
  e.reason = reason;
  e.transient = false;
  return e;
}

function deadlinePassed() {
  return stopError('deadline passed');
}

function aborted() {
  return stopError('aborted');
}

function isStop(e) {
  return !!e && e.code === 'QSTAMP_TRANSPORT' && (e.reason === 'deadline passed' || e.reason === 'aborted');
}

function checkedSignal(signal) {
  if (signal === undefined) return undefined;
  if (!signal || typeof signal !== 'object' || typeof signal.aborted !== 'boolean' ||
    typeof signal.addEventListener !== 'function' || typeof signal.removeEventListener !== 'function') {
    throw new Error('signal must be an AbortSignal');
  }
  return signal;
}

function controlOf(opts, fallbackMs) {
  const o = opts || {};
  let ms = fallbackMs;
  if (o.deadlineMs !== undefined) {
    if (!Number.isSafeInteger(o.deadlineMs) || o.deadlineMs < MIN_DEADLINE_MS || o.deadlineMs > MAX_DEADLINE_MS) {
      throw new Error('deadlineMs is a whole number of milliseconds from ' + MIN_DEADLINE_MS + ' to ' + MAX_DEADLINE_MS);
    }
    ms = o.deadlineMs;
  }
  const signal = checkedSignal(o.signal);
  const deadline = Date.now() + ms;
  return { deadline, cap: deadline, signal };
}

function startClock(ms) {
  const c = scope.getStore();
  if (c && typeof c.cap === 'number') c.deadline = Math.min(c.cap, Date.now() + ms);
}

function current() {
  return scope.getStore() || OPEN;
}

function runWith(ctl, fn) {
  return scope.run(ctl, fn);
}

function outside(fn) {
  return scope.exit(fn);
}

function signalsOf(ctl) {
  return ctl.signal ? [ctl.signal] : [];
}

function stopped(ctl) {
  const c = ctl || current();
  if (signalsOf(c).some((s) => s.aborted)) return aborted();
  if (c.deadline - Date.now() <= 0) return deadlinePassed();
  return null;
}

function left(ctl) {
  return (ctl || current()).deadline - Date.now();
}

function narrowed(ms) {
  const outer = current();
  return { deadline: Math.min(outer.deadline, Date.now() + ms), signal: outer.signal };
}

function noop() {}

function within(value, ctl) {
  const c = ctl || current();
  const promise = Promise.resolve(value);
  const stop = stopped(c);
  if (stop) {
    promise.catch(noop);
    return Promise.reject(stop);
  }
  const signals = signalsOf(c);
  const remaining = c.deadline - Date.now();
  if (!Number.isFinite(remaining) && signals.length === 0) return promise;
  return new Promise((resolve, reject) => {
    let timer = null;
    let settled = false;
    const onAbort = () => finish(reject, aborted());
    function finish(fn, v) {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      for (const s of signals) s.removeEventListener('abort', onAbort);
      if (fn === reject) promise.catch(noop);
      fn(v);
    }
    if (Number.isFinite(remaining)) timer = setTimeout(() => finish(reject, deadlinePassed()), remaining);
    for (const s of signals) s.addEventListener('abort', onAbort, { once: true });
    promise.then((v) => finish(resolve, v), (e) => finish(reject, e));
  });
}

function pause(ms, ctl) {
  let timer = null;
  const wait = new Promise((resolve) => {
    timer = setTimeout(resolve, ms);
  });
  return within(wait, ctl).finally(() => clearTimeout(timer));
}

module.exports = {
  controlOf,
  current,
  runWith,
  outside,
  startClock,
  within,
  pause,
  stopped,
  left,
  narrowed,
  signalsOf,
  isStop,
  deadlinePassed,
  aborted,
  MIN_DEADLINE_MS,
  MAX_DEADLINE_MS,
};
