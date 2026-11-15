//! A wakeable inbox: the agent-side queue of frames the kernel sent us.
//!
//! The agentd used to POLL this queue: the task loop slept 10 ms
//! between checks for the ack of the operation it had just sent, and 20
//! ms between checks for an incoming message. The kernel's answer
//! arrives in ~50 us — so the agent spent up to 10 ms SLEEPING on an
//! answer that was already in the queue. Every checkpoint, every send
//! and every note paid that latency.
//!
//! A condition variable turns the poll into a wakeup: the reader thread
//! signals when it pushes a frame, and the waiter returns as soon as the
//! frame is there.
//!
//! The queue is scanned for the FIRST frame that matches, and ONLY that
//! frame is removed — the frames that do not match stay queued. The old
//! poll popped from the front and DISCARDED everything that did not
//! match, which could swallow an ack that a later step was waiting for.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

pub struct Inbox<T> {
    frames: Mutex<VecDeque<T>>,
    ready: Condvar,
}

impl<T> Default for Inbox<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Inbox<T> {
    pub fn new() -> Self {
        Inbox {
            frames: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
        }
    }

    /// Append a frame and wake one waiter.
    pub fn push(&self, frame: T) {
        self.frames.lock().unwrap().push_back(frame);
        self.ready.notify_one();
    }

    /// Remove and return the first frame that matches `pred`, waiting up
    /// to `timeout` for one to arrive.
    ///
    /// Returns `None` on timeout: the caller decides whether that is an
    /// error (a reply that never came) or a normal end (a message that
    /// never came).
    pub fn pop_matching<F>(&self, timeout: Duration, pred: F) -> Option<T>
    where
        F: Fn(&T) -> bool,
    {
        let deadline = Instant::now() + timeout;
        let mut q = self.frames.lock().unwrap();
        loop {
            if let Some(idx) = q.iter().position(&pred) {
                return q.remove(idx);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (guard, _timeout) = self.ready.wait_timeout(q, deadline - now).unwrap();
            q = guard;
        }
    }

    /// Non-blocking variant: the first matching frame, if it is already
    /// queued.
    pub fn try_pop_matching<F>(&self, pred: F) -> Option<T>
    where
        F: Fn(&T) -> bool,
    {
        let mut q = self.frames.lock().unwrap();
        let idx = q.iter().position(&pred)?;
        q.remove(idx)
    }

    pub fn len(&self) -> usize {
        self.frames.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.lock().unwrap().is_empty()
    }
}
