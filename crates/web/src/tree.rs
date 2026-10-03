//! Generic edits of router.toml as a tree: set, remove, append and move at a
//! path of keys and indices, with values as JSON. Unchanged keys keep their
//! comments and layout (toml_edit); a changed value keeps its decor. The
//! settings page edits every section this way, from the schema.

use serde::Deserialize;
use serde_json::{Map, Value as Json};
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Seg {
    Index(usize),
    Key(String),
}

/// Lists written as `[[name]]` tables when the file doesn't have them yet.
const TABLE_ARRAYS: [&str; 14] = [
    "networks",
    "hosts",
    "tables",
    "forwards",
    "rules",
    "links",
    "routes",
    "vhosts",
    "analyzer.rules",
    "dns.views",
    "dns.overrides",
    "dns.records",
    "proxy.allow",
    "wireguard.peers",
];

fn path_name(path: &[Seg]) -> String {
    path.iter().filter_map(|s| if let Seg::Key(k) = s { Some(k.as_str()) } else { None }).collect::<Vec<_>>().join(".")
}

/// The JSON a TOML value stands for.
pub fn value_json(v: &Value) -> Json {
    match v {
        Value::String(s) => Json::String(s.value().clone()),
        Value::Integer(i) => Json::from(*i.value()),
        Value::Float(f) => Json::from(*f.value()),
        Value::Boolean(b) => Json::Bool(*b.value()),
        Value::Datetime(d) => Json::String(d.value().to_string()),
        Value::Array(a) => Json::Array(a.iter().map(value_json).collect()),
        Value::InlineTable(t) => Json::Object(t.iter().map(|(k, v)| (k.to_string(), value_json(v))).collect()),
    }
}

pub fn item_json(i: &Item) -> Json {
    match i {
        Item::None => Json::Null,
        Item::Value(v) => value_json(v),
        Item::Table(t) => table_json(t),
        Item::ArrayOfTables(a) => Json::Array(a.iter().map(table_json).collect()),
    }
}

fn table_json(t: &Table) -> Json {
    Json::Object(t.iter().map(|(k, v)| (k.to_string(), item_json(v))).collect())
}

/// The whole file as JSON (what the settings page edits).
pub fn doc_json(text: &str) -> Result<Json, String> {
    let doc: DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| e.to_string())?;
    Ok(table_json(doc.as_table()))
}

fn to_value(j: &Json) -> Result<Value, String> {
    Ok(match j {
        Json::Null => return Err("null inside a value".into()),
        Json::Bool(b) => (*b).into(),
        Json::Number(n) => match n.as_i64() {
            Some(i) => i.into(),
            None => n.as_f64().ok_or("bad number")?.into(),
        },
        Json::String(s) => s.as_str().into(),
        Json::Array(a) => {
            let mut arr = Array::new();
            for x in a {
                arr.push(to_value(x)?);
            }
            Value::Array(arr)
        }
        Json::Object(o) => {
            let mut t = InlineTable::new();
            for (k, v) in o.iter().filter(|(_, v)| !v.is_null()) {
                t.insert(k, to_value(v)?);
            }
            Value::InlineTable(t)
        }
    })
}

fn to_table(o: &Map<String, Json>, path: &[Seg]) -> Result<Table, String> {
    let mut t = Table::new();
    merge_table(&mut t, o, path)?;
    Ok(t)
}

/// A new value for an existing one: unchanged stays as written; a changed
/// scalar keeps its comments; tables merge key by key.
fn merge_value(old: &mut Value, new: &Json) -> Result<(), String> {
    if value_json(old) == *new {
        return Ok(());
    }
    match (old, new) {
        (Value::InlineTable(t), Json::Object(o)) => merge_inline(t, o),
        (old, new) => {
            let decor = old.decor().clone();
            *old = to_value(new)?;
            *old.decor_mut() = decor;
            Ok(())
        }
    }
}

fn merge_inline(t: &mut InlineTable, o: &Map<String, Json>) -> Result<(), String> {
    let gone: Vec<String> =
        t.iter().map(|(k, _)| k.to_string()).filter(|k| o.get(k).is_none_or(Json::is_null)).collect();
    for k in gone {
        t.remove(&k);
    }
    for (k, v) in o.iter().filter(|(_, v)| !v.is_null()) {
        match t.get_mut(k) {
            Some(old) => merge_value(old, v)?,
            None => {
                t.insert(k, to_value(v)?);
            }
        }
    }
    t.fmt();
    Ok(())
}

fn merge_table(t: &mut Table, o: &Map<String, Json>, path: &[Seg]) -> Result<(), String> {
    let gone: Vec<String> =
        t.iter().map(|(k, _)| k.to_string()).filter(|k| o.get(k).is_none_or(Json::is_null)).collect();
    for k in gone {
        t.remove(&k);
    }
    for (k, v) in o.iter().filter(|(_, v)| !v.is_null()) {
        let mut p = path.to_vec();
        p.push(Seg::Key(k.clone()));
        set_in_table(t, k, v, &p)?;
    }
    Ok(())
}

/// `t[k] = v`, keeping what is there when it can.
fn set_in_table(t: &mut Table, k: &str, v: &Json, path: &[Seg]) -> Result<(), String> {
    match t.get_mut(k) {
        Some(Item::Table(sub)) => match v {
            Json::Object(o) => merge_table(sub, o, path),
            _ => Err(format!("{} is a table", path_name(path))),
        },
        Some(Item::ArrayOfTables(a)) => match v {
            Json::Array(items) => merge_aot(a, items, path),
            _ => Err(format!("{} is a list of tables", path_name(path))),
        },
        Some(Item::Value(old)) => merge_value(old, v),
        Some(Item::None) | None => {
            let item = new_item(v, path)?;
            t.insert(k, item);
            Ok(())
        }
    }
}

fn merge_aot(a: &mut ArrayOfTables, items: &[Json], path: &[Seg]) -> Result<(), String> {
    while a.len() > items.len() {
        a.remove(a.len() - 1);
    }
    for (i, v) in items.iter().enumerate() {
        let Json::Object(o) = v else { return Err(format!("{}: items are tables", path_name(path))) };
        let mut p = path.to_vec();
        p.push(Seg::Index(i));
        match a.get_mut(i) {
            Some(t) => merge_table(t, o, &p)?,
            None => a.push(to_table(o, &p)?),
        }
    }
    Ok(())
}

/// A new item: sections at the top are tables, the usual lists `[[...]]`,
/// everything deeper inline.
fn new_item(v: &Json, path: &[Seg]) -> Result<Item, String> {
    let name = path_name(path);
    match v {
        Json::Object(o) if path.len() == 1 => Ok(Item::Table(to_table(o, path)?)),
        Json::Array(items) if TABLE_ARRAYS.contains(&name.as_str()) && items.iter().all(Json::is_object) => {
            let mut a = ArrayOfTables::new();
            merge_aot(&mut a, items, path)?;
            Ok(Item::ArrayOfTables(a))
        }
        _ => Ok(Item::Value(to_value(v)?)),
    }
}

enum Node<'a> {
    T(&'a mut Table),
    I(&'a mut InlineTable),
    A(&'a mut ArrayOfTables),
    V(&'a mut Array),
}

fn node_of_item(i: &mut Item) -> Option<Node<'_>> {
    match i {
        Item::Table(t) => Some(Node::T(t)),
        Item::ArrayOfTables(a) => Some(Node::A(a)),
        Item::Value(v) => node_of_value(v),
        Item::None => None,
    }
}

fn node_of_value(v: &mut Value) -> Option<Node<'_>> {
    match v {
        Value::InlineTable(t) => Some(Node::I(t)),
        Value::Array(a) => Some(Node::V(a)),
        _ => None,
    }
}

fn walk<'a>(doc: &'a mut DocumentMut, path: &[Seg]) -> Result<Node<'a>, String> {
    let mut node = Node::T(doc.as_table_mut());
    for (n, seg) in path.iter().enumerate() {
        let here = || path_name(&path[..=n]);
        node = match (node, seg) {
            (Node::T(t), Seg::Key(k)) => {
                if !t.contains_key(k) {
                    // a missing section or sub-table on the way: made empty
                    let item = if n == 0 {
                        Item::Table(Table::new())
                    } else {
                        Item::Value(Value::InlineTable(InlineTable::new()))
                    };
                    t.insert(k, item);
                }
                node_of_item(t.get_mut(k).unwrap()).ok_or_else(|| format!("{} is a value", here()))?
            }
            (Node::I(t), Seg::Key(k)) => {
                if !t.contains_key(k) {
                    t.insert(k, Value::InlineTable(InlineTable::new()));
                }
                node_of_value(t.get_mut(k).unwrap()).ok_or_else(|| format!("{} is a value", here()))?
            }
            (Node::A(a), Seg::Index(i)) => Node::T(a.get_mut(*i).ok_or_else(|| format!("{}: no item {i}", here()))?),
            (Node::V(a), Seg::Index(i)) => {
                node_of_value(a.get_mut(*i).ok_or_else(|| format!("{}: no item {i}", here()))?)
                    .ok_or_else(|| format!("{} is a value", here()))?
            }
            _ => return Err(format!("{}: no such place", here())),
        };
    }
    Ok(node)
}

/// `path = value`; null removes it (a key, or a list item).
pub fn set(doc: &mut DocumentMut, path: &[Seg], v: &Json) -> Result<(), String> {
    let (last, parent) = path.split_last().ok_or("empty path")?;
    match (walk(doc, parent)?, last) {
        (Node::T(t), Seg::Key(k)) if v.is_null() => {
            t.remove(k);
        }
        (Node::T(t), Seg::Key(k)) => set_in_table(t, k, v, path)?,
        (Node::I(t), Seg::Key(k)) if v.is_null() => {
            t.remove(k);
        }
        (Node::I(t), Seg::Key(k)) => match t.get_mut(k) {
            Some(old) => merge_value(old, v)?,
            None => {
                t.insert(k, to_value(v)?);
            }
        },
        (Node::A(a), Seg::Index(i)) if *i < a.len() => match v {
            Json::Null => {
                a.remove(*i);
            }
            Json::Object(o) => merge_table(a.get_mut(*i).unwrap(), o, path)?,
            _ => return Err(format!("{}: items are tables", path_name(path))),
        },
        (Node::V(a), Seg::Index(i)) if *i < a.len() => {
            if v.is_null() {
                a.remove(*i);
            } else {
                merge_value(a.get_mut(*i).unwrap(), v)?;
            }
        }
        _ => return Err(format!("{}: no such place", path_name(path))),
    }
    Ok(())
}

/// Add an item at the end of the list at `path` (made if missing).
pub fn append(doc: &mut DocumentMut, path: &[Seg], v: &Json) -> Result<(), String> {
    let (last, parent) = path.split_last().ok_or("empty path")?;
    if let (Node::T(t), Seg::Key(k)) = (walk(doc, parent)?, last)
        && !t.contains_key(k)
    {
        let item = new_item(&Json::Array(vec![v.clone()]), path)?;
        t.insert(k, item);
        return Ok(());
    }
    match walk(doc, path)? {
        Node::A(a) => {
            let Json::Object(o) = v else { return Err(format!("{}: items are tables", path_name(path))) };
            let mut p = path.to_vec();
            p.push(Seg::Index(a.len()));
            a.push(to_table(o, &p)?);
        }
        Node::V(a) => {
            a.push(to_value(v)?);
            a.fmt();
        }
        _ => return Err(format!("{} is not a list", path_name(path))),
    }
    Ok(())
}

/// Move a list item (rules are first-match: order matters).
pub fn move_item(doc: &mut DocumentMut, path: &[Seg], from: usize, to: usize) -> Result<(), String> {
    match walk(doc, path)? {
        Node::A(a) => {
            if from >= a.len() || to >= a.len() {
                return Err(format!("{}: no item {}", path_name(path), from.max(to)));
            }
            // the file orders tables by position: the slots stay, the tables move
            let mut ts: Vec<Table> = (0..a.len()).map(|_| a.remove(0)).collect();
            let slots: Vec<Option<isize>> = ts.iter().map(Table::position).collect();
            let t = ts.remove(from);
            ts.insert(to, t);
            for (t, p) in ts.iter_mut().zip(slots) {
                t.set_position(p);
            }
            for t in ts {
                a.push(t);
            }
        }
        Node::V(a) => {
            if from >= a.len() || to >= a.len() {
                return Err(format!("{}: no item {}", path_name(path), from.max(to)));
            }
            let v = a.remove(from);
            a.insert(to, v);
        }
        _ => return Err(format!("{} is not a list", path_name(path))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const T: &str = "# top\n[system]\nhostname = \"r\" # keep\ndomain = \"home.arpa\"\n\n\
                     [[networks]]\nname = \"a\" # first\naddress = \"10.0.0.1/24\"\ndhcp = { range = [\"10.0.0.10\", \"10.0.0.20\"] }\n\n\
                     [[networks]]\nname = \"b\"\naddress = \"10.0.1.1/24\"\n\n[dns]\nengine = \"hickory\"\n";

    fn edit(text: &str, f: impl FnOnce(&mut DocumentMut) -> Result<(), String>) -> String {
        let mut d: DocumentMut = text.parse().unwrap();
        f(&mut d).unwrap();
        d.to_string()
    }
    fn p(v: Json) -> Vec<Seg> {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn set_merges_and_keeps_comments() {
        let out = edit(T, |d| {
            set(
                d,
                &p(json!(["networks", 0])),
                &json!({"name": "a", "address": "10.0.0.1/24", "dhcp": {"range": ["10.0.0.10", "10.0.0.30"]}, "kind": "lan"}),
            )
        });
        assert!(out.contains("name = \"a\" # first"), "{out}");
        assert!(out.contains("10.0.0.30") && out.contains("kind = \"lan\""), "{out}");
        assert!(out.contains("# keep") && out.starts_with("# top"));
        // null removes, a scalar keeps its comment
        let out = edit(&out, |d| set(d, &p(json!(["system", "hostname"])), &json!("r2")));
        assert!(out.contains("hostname = \"r2\" # keep"), "{out}");
        let out = edit(&out, |d| set(d, &p(json!(["networks", 1])), &Json::Null));
        assert!(!out.contains("name = \"b\""));
        assert_eq!(doc_json(&out).unwrap()["networks"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn append_and_move_keep_the_file_in_order() {
        let out = edit(T, |d| append(d, &p(json!(["networks"])), &json!({"name": "c", "address": "10.0.2.1/24"})));
        // the new network comes right after the others, before [dns]
        let c = out.find("name = \"c\"").unwrap();
        assert!(c > out.find("name = \"b\"").unwrap() && c < out.find("[dns]").unwrap(), "{out}");
        let out = edit(&out, |d| move_item(d, &p(json!(["networks"])), 2, 0));
        let pos = |n: &str| out.find(&format!("name = \"{n}\"")).unwrap();
        assert!(pos("c") < pos("a") && pos("a") < pos("b") && pos("b") < out.find("[dns]").unwrap(), "{out}");
        // new lists: [[...]] for the usual ones, inline deeper down
        let out =
            edit(&out, |d| append(d, &p(json!(["dns", "overrides"])), &json!({"name": "x.example", "ip": "10.0.0.5"})));
        assert!(out.contains("[[dns.overrides]]"), "{out}");
        let out =
            edit(&out, |d| append(d, &p(json!(["dns", "upstreams"])), &json!({"ip": "1.1.1.1", "tls_name": "one"})));
        assert!(out.contains("upstreams = [{ ip = \"1.1.1.1\", tls_name = \"one\" }]"), "{out}");
        // a new section
        let out = edit(&out, |d| set(d, &p(json!(["ntp"])), &json!({"servers": ["a", "b"]})));
        assert!(out.contains("[ntp]\nservers = [\"a\", \"b\"]"), "{out}");
        let parsed: toml::Table = toml::from_str(&out).unwrap();
        assert_eq!(parsed["networks"].as_array().unwrap().len(), 3);
    }
}
