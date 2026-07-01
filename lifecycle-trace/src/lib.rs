// Copyright(C) Facebook, Inc. and its affiliates.
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const TRACE_ENV: &str = "NARWHAL_LIFECYCLE_TRACE";

static WRITER: OnceLock<Option<TraceWriter>> = OnceLock::new();

struct TraceWriter {
    file: Mutex<BufWriter<File>>,
    seq: AtomicU64,
}

#[derive(Clone)]
enum Value {
    Str(String),
    U64(u64),
    Usize(usize),
    Strs(Vec<String>),
    U64s(Vec<u64>),
}

#[derive(Clone)]
pub struct Event {
    role: &'static str,
    event: &'static str,
    fields: Vec<(&'static str, Value)>,
}

impl Event {
    pub fn new(role: &'static str, event: &'static str) -> Self {
        Self {
            role,
            event,
            fields: Vec::new(),
        }
    }

    pub fn str(mut self, key: &'static str, value: impl Into<String>) -> Self {
        self.fields.push((key, Value::Str(value.into())));
        self
    }

    pub fn u64(mut self, key: &'static str, value: u64) -> Self {
        self.fields.push((key, Value::U64(value)));
        self
    }

    pub fn usize(mut self, key: &'static str, value: usize) -> Self {
        self.fields.push((key, Value::Usize(value)));
        self
    }

    pub fn str_array(mut self, key: &'static str, value: Vec<String>) -> Self {
        self.fields.push((key, Value::Strs(value)));
        self
    }

    pub fn u64_array(mut self, key: &'static str, value: Vec<u64>) -> Self {
        self.fields.push((key, Value::U64s(value)));
        self
    }
}

pub fn enabled() -> bool {
    writer().is_some()
}

pub fn write(event: Event) {
    let Some(writer) = writer() else {
        return;
    };

    let seq = writer.seq.fetch_add(1, Ordering::Relaxed);
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|x| x.as_millis() as u64)
        .unwrap_or_default();
    let line = event.to_json(ts_ms, seq);

    if let Ok(mut file) = writer.file.lock() {
        let _ = file.write_all(line.as_bytes());
        let _ = file.write_all(b"\n");
        let _ = file.flush();
    }
}

fn writer() -> Option<&'static TraceWriter> {
    WRITER
        .get_or_init(|| {
            let path = match env::var(TRACE_ENV) {
                Ok(path) if !path.trim().is_empty() => path,
                _ => return None,
            };
            let file = match OpenOptions::new().create(true).append(true).open(path) {
                Ok(file) => file,
                Err(_) => return None,
            };
            Some(TraceWriter {
                file: Mutex::new(BufWriter::new(file)),
                seq: AtomicU64::new(0),
            })
        })
        .as_ref()
}

impl Event {
    fn to_json(&self, ts_ms: u64, seq: u64) -> String {
        let mut out = String::new();
        out.push('{');
        push_u64(&mut out, "schema_version", 1);
        push_u64(&mut out, "ts_ms", ts_ms);
        push_u64(&mut out, "seq", seq);
        push_str(&mut out, "role", self.role);
        push_str(&mut out, "event", self.event);

        for (key, value) in &self.fields {
            match value {
                Value::Str(value) => push_str(&mut out, key, value),
                Value::U64(value) => push_u64(&mut out, key, *value),
                Value::Usize(value) => push_usize(&mut out, key, *value),
                Value::Strs(value) => push_str_array(&mut out, key, value),
                Value::U64s(value) => push_u64_array(&mut out, key, value),
            }
        }

        out.push('}');
        out
    }
}

fn push_key(out: &mut String, key: &str) {
    if out.len() > 1 {
        out.push(',');
    }
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
}

fn push_str(out: &mut String, key: &str, value: &str) {
    push_key(out, key);
    out.push('"');
    escape_json(out, value);
    out.push('"');
}

fn push_u64(out: &mut String, key: &str, value: u64) {
    push_key(out, key);
    out.push_str(&value.to_string());
}

fn push_usize(out: &mut String, key: &str, value: usize) {
    push_key(out, key);
    out.push_str(&value.to_string());
}

fn push_str_array(out: &mut String, key: &str, value: &[String]) {
    push_key(out, key);
    out.push('[');
    for (i, item) in value.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        escape_json(out, item);
        out.push('"');
    }
    out.push(']');
}

fn push_u64_array(out: &mut String, key: &str, value: &[u64]) {
    push_key(out, key);
    out.push('[');
    for (i, item) in value.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&item.to_string());
    }
    out.push(']');
}

fn escape_json(out: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}
