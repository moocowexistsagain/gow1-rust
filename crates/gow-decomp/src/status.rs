//! Per-function progress tracking, so `gowd gen` can be re-run inside a loop
//! without clobbering curated work.
//!
//! `out/rust/status.txt` format (one line per function, `#` comments allowed):
//!
//! ```text
//! 0x001129b0 done          # verified against the original by hand
//! 0x00112a40 in-progress
//! 0x00112ab8 todo
//! ```

use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Todo,
    InProgress,
    Done,
}

impl State {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            State::Todo => "todo",
            State::InProgress => "in-progress",
            State::Done => "done",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "todo" | "new" | "" => State::Todo,
            "in-progress" | "wip" | "in_progress" => State::InProgress,
            "done" | "complete" | "matches" => State::Done,
            _ => return None,
        })
    }
}

#[derive(Clone, Default)]
pub struct StatusFile {
    entries: BTreeMap<u32, (State, Option<String>)>,
}

impl StatusFile {
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(t) => Ok(Self::parse(&t)),
            // Absent status file is normal on a fresh checkout.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut entries = BTreeMap::new();
        for line in text.lines() {
            let (body, note) = match line.split_once('#') {
                Some((a, b)) => (a, Some(b.trim().to_string())),
                None => (line, None),
            };
            let mut it = body.split_whitespace();
            let (Some(addr), Some(state)) = (it.next(), it.next()) else {
                continue;
            };
            let Some(addr) = parse_addr(addr) else {
                continue;
            };
            let Some(state) = State::parse(state) else {
                eprintln!("status: unknown state {state:?} for {addr:#x}");
                continue;
            };
            entries.insert(addr, (state, note));
        }
        Self { entries }
    }

    #[must_use]
    pub fn is_done(&self, addr: u32) -> bool {
        matches!(self.entries.get(&addr), Some((State::Done, _)))
    }

    #[must_use]
    pub fn state(&self, addr: u32) -> State {
        self.entries
            .get(&addr)
            .map(|(s, _)| *s)
            .unwrap_or(State::Todo)
    }

    #[must_use]
    pub fn counts(&self) -> (usize, usize, usize) {
        let mut t = (0, 0, 0);
        for (s, _) in self.entries.values() {
            match s {
                State::Todo => t.0 += 1,
                State::InProgress => t.1 += 1,
                State::Done => t.2 += 1,
            }
        }
        t
    }

    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::from(
            "# gow1-rust decompilation status\n# <address> <todo|in-progress|done> [# note]\n",
        );
        for (addr, (s, note)) in &self.entries {
            let _ = write::fmt_line(&mut out, *addr, s.as_str(), note.as_deref());
        }
        out
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        std::fs::write(path, self.to_text()).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Ensure every discovered function has a line, preserving existing states.
    pub fn seed(&mut self, addrs: impl IntoIterator<Item = u32>) -> usize {
        let mut added = 0;
        for a in addrs {
            if let std::collections::btree_map::Entry::Vacant(e) = self.entries.entry(a) {
                e.insert((State::Todo, None));
                added += 1;
            }
        }
        added
    }
}

mod write {
    use std::fmt::Write as _;
    pub fn fmt_line(
        out: &mut String,
        addr: u32,
        state: &str,
        note: Option<&str>,
    ) -> std::fmt::Result {
        write!(out, "{addr:#010x} {state}")?;
        if let Some(n) = note {
            write!(out, " # {n}")?;
        }
        out.push('\n');
        Ok(())
    }
}

fn parse_addr(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_seed_is_idempotent() {
        let mut s = StatusFile::parse("0x1000 done # verified\n0x1040 wip\n\n# comment\n");
        assert_eq!(s.state(0x1000), State::Done);
        assert_eq!(s.state(0x1040), State::InProgress);
        assert_eq!(s.state(0x2000), State::Todo);
        assert_eq!(s.seed([0x1000, 0x2000]), 1);
        assert_eq!(
            s.seed([0x1000, 0x2000]),
            0,
            "seeding twice must add nothing"
        );
        assert_eq!(s.counts(), (1, 1, 1));
        let text = s.to_text();
        assert_eq!(StatusFile::parse(&text).counts(), (1, 1, 1));
        assert!(text.contains("0x00001000 done # verified"));
    }
}
