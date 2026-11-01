//! A Mercurial history built from a structured description, and the changegroup a pull of it
//! receives.
//!
//! The model (or a static/script handler) describes commits — author, date, message, parents,
//! branch, and the files each one adds, changes or removes as **text** — and this module derives
//! everything Mercurial computes for itself: filelog, manifest and changelog revision texts, and
//! their revlog nodes, `sha1(min(p1, p2) + max(p1, p2) + text)` exactly as
//! `mercurial/utils/storageutil.py::hashrevisionsha1` defines it. Nothing is stored: every request
//! rebuilds the history from the action that answered it, so a description that is the same on
//! every request yields the same nodes on every request.
//!
//! The changegroup is version 1 (`cg1`), the format a bundle1 `getbundle` carries: a changelog
//! group, a manifest group and one group per file, each chunk a 4-byte length, an 80-byte header
//! (`node`, `p1`, `p2`, `linknode`) and a delta against the previous chunk in its group (the
//! revision's `p1` for the first). Every delta here is one hunk replacing the whole base with the
//! full text, which is always valid and keeps the encoder free of a diff algorithm.
//!
//! Every input is bounded (see the `MAX_*` constants) and refused, never truncated: a history the
//! server cannot represent faithfully is an error, not a smaller history.

use serde_json::Value;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

/// A 20-byte revlog node.
pub type Node = [u8; 20];

/// Mercurial's null node: the parent of a root, and the head of an empty repository.
pub const NULL_NODE: Node = [0u8; 20];

/// Most commits one description may hold.
pub const MAX_COMMITS: usize = 256;
/// Most `files` plus `removed` entries one commit may list.
pub const MAX_CHANGES_PER_COMMIT: usize = 256;
/// Most distinct paths across the whole history.
pub const MAX_PATHS: usize = 1024;
/// Longest path, in bytes.
pub const MAX_PATH_BYTES: usize = 255;
/// Largest single file content, in bytes.
pub const MAX_FILE_BYTES: usize = 1024 * 1024;
/// Largest sum of every `content` in the description, in bytes.
pub const MAX_TOTAL_CONTENT_BYTES: usize = 8 * 1024 * 1024;
/// Largest sum of every distinct manifest text the history produces, in bytes. A manifest
/// lists every file of a commit, so it is the one cost that grows as commits x paths rather
/// than with what the description spelled out.
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
/// Longest commit message, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Longest author, in bytes.
pub const MAX_AUTHOR_BYTES: usize = 512;
/// Longest commit `id` label, in bytes.
pub const MAX_ID_BYTES: usize = 64;
/// Longest branch name, in bytes.
pub const MAX_BRANCH_BYTES: usize = 64;

/// Author used when a commit names none.
pub const DEFAULT_AUTHOR: &str = "NetGet <netget@localhost>";
/// Commit time (Unix seconds, UTC) used when a commit names none. Fixed, so an undated
/// description still yields the same nodes on every request.
pub const DEFAULT_TIMESTAMP: i64 = 1_700_000_000;

/// Largest timezone offset Mercurial accepts (`dateutil.parsedate`), in seconds.
const MAX_TZ_OFFSET_SECS: i64 = 50_400;

/// Why a repository description was refused. The text names the offending commit or path; it
/// is for the server log, never for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidRepository(pub String);

impl fmt::Display for InvalidRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InvalidRepository {}

fn invalid<T>(message: impl Into<String>) -> Result<T, InvalidRepository> {
    Err(InvalidRepository(message.into()))
}

/// Why a changegroup could not be built for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangegroupError {
    /// The client asked for a head the history does not contain.
    UnknownHead(String),
}

impl fmt::Display for ChangegroupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChangegroupError::UnknownHead(node) => write!(f, "requested head {node} is unknown"),
        }
    }
}

impl std::error::Error for ChangegroupError {}

/// Lowercase hex of a node.
pub fn hex(node: &Node) -> String {
    hex::encode(node)
}

/// Parse a 40-character hex node.
pub fn parse_node(text: &str) -> Option<Node> {
    let text = text.trim();
    if text.len() != 40 {
        return None;
    }
    let bytes = hex::decode(text).ok()?;
    bytes.try_into().ok()
}

/// Mercurial's revision hash: SHA-1 over the two parents in sorted order, then the text.
pub fn revision_node(p1: &Node, p2: &Node, text: &[u8]) -> Node {
    let (a, b) = if p1 <= p2 { (p1, p2) } else { (p2, p1) };
    let mut hasher = Sha1::new();
    hasher.update(a);
    hasher.update(b);
    hasher.update(text);
    hasher.finalize().into()
}

/// One manifest entry: the file's filelog node and whether it is executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    node: Node,
    executable: bool,
}

/// A revlog revision: parents and full text.
#[derive(Debug, Clone)]
struct Revision {
    p1: Node,
    p2: Node,
    text: Vec<u8>,
}

/// One changeset of the history.
#[derive(Debug, Clone)]
pub struct Changeset {
    /// The label the description gave it (or `#<index>` when it gave none).
    pub id: String,
    pub node: Node,
    pub p1: Node,
    pub p2: Node,
    pub branch: String,
    parents: Vec<usize>,
    manifest: Node,
    /// Files this changeset touched, sorted: changed, added or removed relative to `p1`.
    touched: Vec<String>,
    text: Vec<u8>,
    tree: BTreeMap<String, Entry>,
}

/// A whole history, with every revlog text and node derived.
#[derive(Debug, Clone, Default)]
pub struct Repository {
    changesets: Vec<Changeset>,
    index: HashMap<Node, usize>,
    manifests: HashMap<Node, Revision>,
    filelogs: BTreeMap<String, HashMap<Node, Revision>>,
}

impl Repository {
    /// Build the history an `hg_repository` action describes.
    pub fn from_description(description: &Value) -> Result<Self, InvalidRepository> {
        let commits = match description.get("commits") {
            Some(Value::Array(commits)) => commits,
            Some(_) => return invalid("`commits` must be an array"),
            None => return invalid("missing `commits`"),
        };
        if commits.len() > MAX_COMMITS {
            return invalid(format!(
                "{} commits described; at most {} are served",
                commits.len(),
                MAX_COMMITS
            ));
        }

        let mut repo = Repository::default();
        let mut ids: HashMap<String, usize> = HashMap::new();
        let mut paths: HashSet<String> = HashSet::new();
        let mut content_bytes = 0usize;
        let mut manifest_bytes = 0usize;

        for (i, commit) in commits.iter().enumerate() {
            let obj = commit
                .as_object()
                .ok_or_else(|| InvalidRepository(format!("commit #{i} is not an object")))?;

            let id = match obj.get("id") {
                None | Some(Value::Null) => format!("#{i}"),
                Some(Value::String(s)) => {
                    if s.is_empty() || s.len() > MAX_ID_BYTES {
                        return invalid(format!(
                            "commit #{i}: `id` must be 1 to {MAX_ID_BYTES} bytes"
                        ));
                    }
                    s.clone()
                }
                Some(_) => return invalid(format!("commit #{i}: `id` must be a string")),
            };
            if ids.contains_key(&id) {
                return invalid(format!("commit id {id:?} is used twice"));
            }
            let label = format!("commit {id:?}");

            let parents: Vec<usize> = match obj.get("parents") {
                None | Some(Value::Null) => {
                    if i == 0 {
                        Vec::new()
                    } else {
                        vec![i - 1]
                    }
                }
                Some(Value::Array(list)) => {
                    if list.len() > 2 {
                        return invalid(format!("{label}: a commit has at most two parents"));
                    }
                    let mut parents = Vec::new();
                    for parent in list {
                        let name = parent.as_str().ok_or_else(|| {
                            InvalidRepository(format!("{label}: parents must be commit ids"))
                        })?;
                        let index = *ids.get(name).ok_or_else(|| {
                            InvalidRepository(format!(
                                "{label}: parent {name:?} is not an earlier commit (parents \
                                 must be listed before their children)"
                            ))
                        })?;
                        if parents.contains(&index) {
                            return invalid(format!("{label}: parent {name:?} is listed twice"));
                        }
                        parents.push(index);
                    }
                    parents
                }
                Some(_) => return invalid(format!("{label}: `parents` must be an array")),
            };

            let author = match obj.get("author") {
                None | Some(Value::Null) => DEFAULT_AUTHOR.to_string(),
                Some(Value::String(s)) => s.trim().to_string(),
                Some(_) => return invalid(format!("{label}: `author` must be a string")),
            };
            if author.is_empty()
                || author.len() > MAX_AUTHOR_BYTES
                || author.contains(['\n', '\r', '\0'])
            {
                return invalid(format!(
                    "{label}: `author` must be 1 to {MAX_AUTHOR_BYTES} bytes on one line"
                ));
            }

            let message = match obj.get("message") {
                Some(Value::String(s)) => strip_description(s),
                _ => return invalid(format!("{label}: `message` must be a string")),
            };
            if message.is_empty() || message.len() > MAX_MESSAGE_BYTES || message.contains('\0') {
                return invalid(format!(
                    "{label}: `message` must be 1 to {MAX_MESSAGE_BYTES} bytes of text"
                ));
            }

            let (time, tz) = parse_date(obj.get("date"))
                .map_err(|e| InvalidRepository(format!("{label}: {e}")))?;

            let branch = match obj.get("branch") {
                None | Some(Value::Null) => "default".to_string(),
                Some(Value::String(s)) => s.clone(),
                Some(_) => return invalid(format!("{label}: `branch` must be a string")),
            };
            validate_branch(&branch).map_err(|e| InvalidRepository(format!("{label}: {e}")))?;

            let files = match obj.get("files") {
                None | Some(Value::Null) => &[][..],
                Some(Value::Array(files)) => files.as_slice(),
                Some(_) => return invalid(format!("{label}: `files` must be an array")),
            };
            let removed = match obj.get("removed") {
                None | Some(Value::Null) => &[][..],
                Some(Value::Array(removed)) => removed.as_slice(),
                Some(_) => return invalid(format!("{label}: `removed` must be an array")),
            };
            if files.len() + removed.len() > MAX_CHANGES_PER_COMMIT {
                return invalid(format!(
                    "{label}: {} changes listed; at most {MAX_CHANGES_PER_COMMIT} per commit",
                    files.len() + removed.len()
                ));
            }

            let p1 = parents.first().map(|&p| &repo.changesets[p]);
            let p2 = parents.get(1).map(|&p| &repo.changesets[p]);
            let p1_tree = p1.map(|c| &c.tree);
            let p2_tree = p2.map(|c| &c.tree);

            // A commit starts from its first parent's files; a merge also keeps every path only
            // its second parent has. A path both parents have keeps the first parent's version
            // unless the commit lists it.
            let mut tree: BTreeMap<String, Entry> = p1_tree.cloned().unwrap_or_default();
            if let Some(p2_tree) = p2_tree {
                for (path, entry) in p2_tree {
                    tree.entry(path.clone()).or_insert(*entry);
                }
            }

            let mut listed: HashSet<&str> = HashSet::new();
            for path in removed {
                let path = path.as_str().ok_or_else(|| {
                    InvalidRepository(format!("{label}: `removed` entries must be paths"))
                })?;
                if !listed.insert(path) {
                    return invalid(format!("{label}: path {path:?} is listed twice"));
                }
                if tree.remove(path).is_none() {
                    return invalid(format!(
                        "{label}: removes {path:?}, which its parents do not have"
                    ));
                }
            }

            let mut new_files: Vec<(String, Vec<u8>, bool)> = Vec::with_capacity(files.len());
            for file in files {
                let file = file.as_object().ok_or_else(|| {
                    InvalidRepository(format!(
                        "{label}: `files` entries must be objects with `path` and `content`"
                    ))
                })?;
                let path = file
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| InvalidRepository(format!("{label}: a file has no `path`")))?;
                validate_path(path).map_err(|e| InvalidRepository(format!("{label}: {e}")))?;
                if !listed.insert(path) {
                    return invalid(format!("{label}: path {path:?} is listed twice"));
                }
                let content = file.get("content").and_then(Value::as_str).ok_or_else(|| {
                    InvalidRepository(format!("{label}: file {path:?} has no text `content`"))
                })?;
                if content.len() > MAX_FILE_BYTES {
                    return invalid(format!(
                        "{label}: file {path:?} is {} bytes; at most {MAX_FILE_BYTES}",
                        content.len()
                    ));
                }
                content_bytes += content.len();
                if content_bytes > MAX_TOTAL_CONTENT_BYTES {
                    return invalid(format!(
                        "file contents exceed {MAX_TOTAL_CONTENT_BYTES} bytes in total"
                    ));
                }
                let executable = match file.get("executable") {
                    None | Some(Value::Null) => false,
                    Some(Value::Bool(b)) => *b,
                    Some(_) => {
                        return invalid(format!(
                            "{label}: file {path:?}: `executable` must be true or false"
                        ))
                    }
                };
                new_files.push((path.to_string(), filelog_text(content), executable));
            }

            for (path, text, executable) in new_files {
                let mut fp1 = p1_tree
                    .and_then(|t| t.get(&path))
                    .map_or(NULL_NODE, |e| e.node);
                let mut fp2 = p2_tree
                    .and_then(|t| t.get(&path))
                    .map_or(NULL_NODE, |e| e.node);
                if fp2 == fp1 {
                    fp2 = NULL_NODE;
                }
                if fp1 == NULL_NODE {
                    std::mem::swap(&mut fp1, &mut fp2);
                }
                let filelog = repo.filelogs.entry(path.clone()).or_default();
                let unchanged = fp2 == NULL_NODE
                    && fp1 != NULL_NODE
                    && filelog.get(&fp1).is_some_and(|r| r.text == text);
                let node = if unchanged {
                    fp1
                } else {
                    let node = revision_node(&fp1, &fp2, &text);
                    filelog.entry(node).or_insert(Revision {
                        p1: fp1,
                        p2: fp2,
                        text,
                    });
                    node
                };
                if !paths.contains(&path) {
                    if paths.len() >= MAX_PATHS {
                        return invalid(format!(
                            "more than {MAX_PATHS} distinct paths in the history"
                        ));
                    }
                    paths.insert(path.clone());
                }
                check_path_conflicts(&tree, &path)
                    .map_err(|e| InvalidRepository(format!("{label}: {e}")))?;
                tree.insert(path, Entry { node, executable });
            }

            // Touched: every path whose entry differs from the first parent's, and every path a
            // parent had that this commit no longer has.
            let mut touched: BTreeSet<String> = BTreeSet::new();
            for (path, entry) in &tree {
                if p1_tree.and_then(|t| t.get(path)) != Some(entry) {
                    touched.insert(path.clone());
                }
            }
            for parent_tree in [p1_tree, p2_tree].into_iter().flatten() {
                for path in parent_tree.keys() {
                    if !tree.contains_key(path) {
                        touched.insert(path.clone());
                    }
                }
            }

            let manifest_text = manifest_text(&tree);
            let mp1 = p1.map_or(NULL_NODE, |c| c.manifest);
            let mut mp2 = p2.map_or(NULL_NODE, |c| c.manifest);
            if mp2 == mp1 {
                mp2 = NULL_NODE;
            }
            let reuse = mp2 == NULL_NODE
                && mp1 != NULL_NODE
                && repo
                    .manifests
                    .get(&mp1)
                    .is_some_and(|r| r.text == manifest_text);
            let manifest = if reuse {
                mp1
            } else {
                let node = revision_node(&mp1, &mp2, &manifest_text);
                if !repo.manifests.contains_key(&node) {
                    manifest_bytes += manifest_text.len();
                    if manifest_bytes > MAX_MANIFEST_BYTES {
                        return invalid(format!(
                            "the history's manifests exceed {MAX_MANIFEST_BYTES} bytes"
                        ));
                    }
                    repo.manifests.insert(
                        node,
                        Revision {
                            p1: mp1,
                            p2: mp2,
                            text: manifest_text,
                        },
                    );
                }
                node
            };

            let touched: Vec<String> = touched.into_iter().collect();
            let text = changelog_text(&manifest, &author, time, tz, &branch, &touched, &message);
            let cp1 = p1.map_or(NULL_NODE, |c| c.node);
            let cp2 = p2.map_or(NULL_NODE, |c| c.node);
            let node = revision_node(&cp1, &cp2, &text);
            if let Some(&other) = repo.index.get(&node) {
                return invalid(format!(
                    "{label} is identical to commit {:?} (same parents, files, author, date and \
                     message)",
                    repo.changesets[other].id
                ));
            }

            repo.index.insert(node, i);
            ids.insert(id.clone(), i);
            repo.changesets.push(Changeset {
                id,
                node,
                p1: cp1,
                p2: cp2,
                branch,
                parents,
                manifest,
                touched,
                text,
                tree,
            });
        }

        Ok(repo)
    }

    /// The changesets, in revision order.
    pub fn changesets(&self) -> &[Changeset] {
        &self.changesets
    }

    /// Whether the history has no commits.
    pub fn is_empty(&self) -> bool {
        self.changesets.is_empty()
    }

    /// Indices of changesets with no children.
    fn head_indices(&self) -> Vec<usize> {
        let mut has_child = vec![false; self.changesets.len()];
        for cs in &self.changesets {
            for &p in &cs.parents {
                has_child[p] = true;
            }
        }
        (0..self.changesets.len())
            .filter(|&i| !has_child[i])
            .collect()
    }

    /// The repository heads, tipmost first, as `repo.heads()` returns them. The null node for
    /// an empty repository.
    pub fn heads(&self) -> Vec<Node> {
        let heads: Vec<Node> = self
            .head_indices()
            .into_iter()
            .rev()
            .map(|i| self.changesets[i].node)
            .collect();
        if heads.is_empty() {
            vec![NULL_NODE]
        } else {
            heads
        }
    }

    /// Each branch with its heads (changesets with no child on the same branch), in revision
    /// order, branches sorted by name.
    pub fn branch_heads(&self) -> BTreeMap<String, Vec<Node>> {
        let mut has_branch_child = vec![false; self.changesets.len()];
        for cs in &self.changesets {
            for &p in &cs.parents {
                if self.changesets[p].branch == cs.branch {
                    has_branch_child[p] = true;
                }
            }
        }
        let mut map: BTreeMap<String, Vec<Node>> = BTreeMap::new();
        for (i, cs) in self.changesets.iter().enumerate() {
            if !has_branch_child[i] {
                map.entry(cs.branch.clone()).or_default().push(cs.node);
            }
        }
        map
    }

    /// Whether the history contains `node`.
    pub fn contains(&self, node: &Node) -> bool {
        self.index.contains_key(node)
    }

    /// Resolve a revision symbol the way `hg lookup` does, for the symbols a remote can mean:
    /// `tip`, `null`, a revision number, a full node, a branch name (its tipmost head), or an
    /// unambiguous node prefix.
    pub fn lookup(&self, key: &str) -> Option<Node> {
        let key = key.trim();
        match key {
            "tip" => return Some(self.changesets.last().map_or(NULL_NODE, |c| c.node)),
            "null" => return Some(NULL_NODE),
            _ => {}
        }
        if let Ok(rev) = key.parse::<i64>() {
            if rev.to_string() == key {
                if rev == -1 {
                    return Some(NULL_NODE);
                }
                if rev >= 0 && (rev as usize) < self.changesets.len() {
                    return Some(self.changesets[rev as usize].node);
                }
            }
        }
        if let Some(node) = parse_node(key) {
            if node == NULL_NODE || self.contains(&node) {
                return Some(node);
            }
        }
        if let Some(heads) = self.branch_heads().get(key) {
            return heads.last().copied();
        }
        let prefix = key.to_ascii_lowercase();
        if !prefix.is_empty() && prefix.len() < 40 && prefix.bytes().all(|b| b.is_ascii_hexdigit())
        {
            let mut matches = self
                .changesets
                .iter()
                .filter(|c| hex(&c.node).starts_with(&prefix));
            if let (Some(only), None) = (matches.next(), matches.next()) {
                return Some(only.node);
            }
        }
        None
    }

    /// Every changeset that is `roots` or an ancestor of one of them.
    fn ancestors(&self, roots: impl IntoIterator<Item = usize>) -> Vec<bool> {
        let mut seen = vec![false; self.changesets.len()];
        let mut stack: Vec<usize> = roots.into_iter().collect();
        while let Some(i) = stack.pop() {
            if !seen[i] {
                seen[i] = true;
                stack.extend(self.changesets[i].parents.iter().copied());
            }
        }
        seen
    }

    /// The version-1 changegroup a client holding `common` receives when it asks for `heads`
    /// (every head when `heads` is empty). Nodes in `common` the history does not contain are
    /// ignored, as Mercurial's own server ignores them.
    pub fn changegroup(
        &self,
        heads: &[Node],
        common: &[Node],
    ) -> Result<Vec<u8>, ChangegroupError> {
        let mut head_indices = Vec::new();
        for head in heads {
            if *head == NULL_NODE {
                continue;
            }
            match self.index.get(head) {
                Some(&i) => head_indices.push(i),
                None => return Err(ChangegroupError::UnknownHead(hex(head))),
            }
        }
        if heads.is_empty() {
            head_indices = self.head_indices();
        }
        let common_indices: Vec<usize> = common
            .iter()
            .filter_map(|node| self.index.get(node).copied())
            .collect();

        let has = self.ancestors(common_indices);
        let wanted = self.ancestors(head_indices);
        let missing: Vec<usize> = (0..self.changesets.len())
            .filter(|&i| wanted[i] && !has[i])
            .collect();

        // What the client already holds: the manifests and file revisions of every changeset
        // it has. Only what is not there goes into the group.
        let mut client_manifests: HashSet<Node> = HashSet::new();
        let mut client_files: HashSet<(&str, Node)> = HashSet::new();
        for (i, cs) in self.changesets.iter().enumerate() {
            if has[i] {
                client_manifests.insert(cs.manifest);
                for (path, entry) in &cs.tree {
                    client_files.insert((path.as_str(), entry.node));
                }
            }
        }

        let mut out = ChunkWriter::default();

        // Changelog.
        let mut prev: Option<Node> = None;
        for &i in &missing {
            let cs = &self.changesets[i];
            let base = prev.unwrap_or(cs.p1);
            let base_text = self.changeset_text(&base);
            out.revision(&cs.node, &cs.p1, &cs.p2, &cs.node, base_text, &cs.text);
            prev = Some(cs.node);
        }
        out.close();

        // Manifests, each linked to the first missing changeset that uses it.
        let mut prev: Option<Node> = None;
        let mut sent: HashSet<Node> = HashSet::new();
        for &i in &missing {
            let cs = &self.changesets[i];
            if client_manifests.contains(&cs.manifest) || !sent.insert(cs.manifest) {
                continue;
            }
            let rev = &self.manifests[&cs.manifest];
            let base = prev.unwrap_or(rev.p1);
            let base_text = self.manifests.get(&base).map_or(&[][..], |r| &r.text[..]);
            out.revision(
                &cs.manifest,
                &rev.p1,
                &rev.p2,
                &cs.node,
                base_text,
                &rev.text,
            );
            prev = Some(cs.manifest);
        }
        out.close();

        // Filelogs. A file revision the client lacks first appears in a missing changeset that
        // touched it, so walking each missing changeset's touched files in revision order finds
        // every one, parents before children.
        let mut per_file: BTreeMap<&str, Vec<(Node, Node)>> = BTreeMap::new();
        let mut sent: HashSet<(&str, Node)> = HashSet::new();
        for &i in &missing {
            let cs = &self.changesets[i];
            for path in &cs.touched {
                let Some(entry) = cs.tree.get(path) else {
                    continue;
                };
                let key = (path.as_str(), entry.node);
                if client_files.contains(&key) || !sent.insert(key) {
                    continue;
                }
                per_file
                    .entry(path.as_str())
                    .or_default()
                    .push((entry.node, cs.node));
            }
        }
        for (path, revisions) in per_file {
            let filelog = &self.filelogs[path];
            out.filename(path.as_bytes());
            let mut prev: Option<Node> = None;
            for (node, linknode) in revisions {
                let rev = &filelog[&node];
                let base = prev.unwrap_or(rev.p1);
                let base_text = filelog.get(&base).map_or(&[][..], |r| &r.text[..]);
                out.revision(&node, &rev.p1, &rev.p2, &linknode, base_text, &rev.text);
                prev = Some(node);
            }
            out.close();
        }
        out.close();

        Ok(out.bytes)
    }

    fn changeset_text(&self, node: &Node) -> &[u8] {
        self.index
            .get(node)
            .map_or(&[][..], |&i| &self.changesets[i].text[..])
    }
}

/// The changegroup of an empty pull: an empty changelog group, an empty manifest group, and
/// the end of the file groups.
pub fn empty_changegroup() -> Vec<u8> {
    vec![0u8; 12]
}

/// Chunk framing.
///
/// No size check of its own: the changegroup is bounded by what the description may hold —
/// changelog texts by commits, author, message and touched paths; manifests by
/// [`MAX_MANIFEST_BYTES`]; file revisions by [`MAX_TOTAL_CONTENT_BYTES`]; headers by
/// [`MAX_COMMITS`] x [`MAX_CHANGES_PER_COMMIT`] chunks — some tens of MiB at the very worst,
/// and the peer chooses only which part of it to receive. Every chunk is far below the
/// `i32` its length is written as.
#[derive(Default)]
struct ChunkWriter {
    bytes: Vec<u8>,
}

impl ChunkWriter {
    fn length(&mut self, payload_len: usize) {
        self.bytes
            .extend_from_slice(&((payload_len + 4) as i32).to_be_bytes());
    }

    fn close(&mut self) {
        self.bytes.extend_from_slice(&0i32.to_be_bytes());
    }

    fn filename(&mut self, name: &[u8]) {
        self.length(name.len());
        self.bytes.extend_from_slice(name);
    }

    /// One delta chunk: the 80-byte cg1 header, then a single hunk replacing all of
    /// `base_text` with `text`.
    fn revision(
        &mut self,
        node: &Node,
        p1: &Node,
        p2: &Node,
        linknode: &Node,
        base_text: &[u8],
        text: &[u8],
    ) {
        self.length(80 + 12 + text.len());
        self.bytes.extend_from_slice(node);
        self.bytes.extend_from_slice(p1);
        self.bytes.extend_from_slice(p2);
        self.bytes.extend_from_slice(linknode);
        self.bytes.extend_from_slice(&0i32.to_be_bytes());
        self.bytes
            .extend_from_slice(&(base_text.len() as i32).to_be_bytes());
        self.bytes
            .extend_from_slice(&(text.len() as i32).to_be_bytes());
        self.bytes.extend_from_slice(text);
    }
}

/// A filelog revision text. Content that itself begins with the metadata marker `\x01\n` is
/// wrapped in an empty metadata block, as `filelog.add` does, so it is not read as metadata.
fn filelog_text(content: &str) -> Vec<u8> {
    let content = content.as_bytes();
    if content.starts_with(b"\x01\n") {
        let mut text = b"\x01\n\x01\n".to_vec();
        text.extend_from_slice(content);
        text
    } else {
        content.to_vec()
    }
}

/// `path\0<hex node><flags>\n` per file, sorted by path.
fn manifest_text(tree: &BTreeMap<String, Entry>) -> Vec<u8> {
    let mut text = Vec::new();
    for (path, entry) in tree {
        text.extend_from_slice(path.as_bytes());
        text.push(0);
        text.extend_from_slice(hex(&entry.node).as_bytes());
        if entry.executable {
            text.push(b'x');
        }
        text.push(b'\n');
    }
    text
}

/// The changelog revision text, as `changelog.add` joins it.
fn changelog_text(
    manifest: &Node,
    author: &str,
    time: i64,
    tz: i64,
    branch: &str,
    touched: &[String],
    message: &str,
) -> Vec<u8> {
    let mut date = format!("{time} {tz}");
    if branch != "default" {
        // `encodeextra`: branch names are validated to need no escaping.
        date.push_str(" branch:");
        date.push_str(branch);
    }
    let mut lines: Vec<&str> = Vec::with_capacity(touched.len() + 5);
    let manifest_hex = hex(manifest);
    lines.push(&manifest_hex);
    lines.push(author);
    lines.push(&date);
    lines.extend(touched.iter().map(String::as_str));
    lines.push("");
    lines.push(message);
    lines.join("\n").into_bytes()
}

/// `changelog.stripdesc`: strip trailing whitespace from every line and blank lines from both
/// ends.
fn strip_description(message: &str) -> String {
    let joined: Vec<&str> = message.lines().map(str::trim_end).collect();
    joined.join("\n").trim_matches('\n').to_string()
}

/// A commit date: Unix seconds (UTC), an RFC 3339 timestamp, or Mercurial's own
/// `"<seconds> <offset>"`. Returns Mercurial's pair: seconds, and the offset in seconds *west*
/// of UTC.
fn parse_date(value: Option<&Value>) -> Result<(i64, i64), String> {
    let (time, tz) = match value {
        None | Some(Value::Null) => (DEFAULT_TIMESTAMP, 0),
        Some(Value::Number(n)) => (
            n.as_i64()
                .ok_or("`date` must be whole Unix seconds".to_string())?,
            0,
        ),
        Some(Value::String(s)) => {
            let s = s.trim();
            let mut parts = s.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some(t), Some(z), None)
                    if t.parse::<i64>().is_ok() && z.parse::<i64>().is_ok() =>
                {
                    (t.parse::<i64>().unwrap_or(0), z.parse::<i64>().unwrap_or(0))
                }
                _ => {
                    let parsed = chrono::DateTime::parse_from_rfc3339(s).map_err(|_| {
                        format!(
                            "`date` {s:?} is neither Unix seconds nor an RFC 3339 timestamp \
                             such as 2026-10-31T12:00:00+01:00"
                        )
                    })?;
                    (
                        parsed.timestamp(),
                        -i64::from(parsed.offset().local_minus_utc()),
                    )
                }
            }
        }
        Some(_) => return Err("`date` must be Unix seconds or an RFC 3339 string".to_string()),
    };
    if time < i64::from(i32::MIN) || time > i64::from(i32::MAX) {
        return Err("`date` exceeds the 32 bits Mercurial stores".to_string());
    }
    if tz.abs() > MAX_TZ_OFFSET_SECS {
        return Err("`date` has a timezone offset beyond 14 hours".to_string());
    }
    Ok((time, tz))
}

fn validate_branch(branch: &str) -> Result<(), String> {
    if branch.is_empty() || branch.len() > MAX_BRANCH_BYTES {
        return Err(format!("branch name must be 1 to {MAX_BRANCH_BYTES} bytes"));
    }
    if matches!(branch, "." | "null" | "tip") {
        return Err(format!("branch name {branch:?} is reserved"));
    }
    if branch.parse::<i64>().is_ok() {
        return Err(format!(
            "branch name {branch:?} would be read as a revision number"
        ));
    }
    if !branch
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/' | b'+'))
    {
        return Err(format!(
            "branch name {branch:?} may use only letters, digits and - _ . / +"
        ));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return Err(format!("path must be 1 to {MAX_PATH_BYTES} bytes"));
    }
    if path.contains(['\0', '\n', '\r', '\\']) {
        return Err(format!(
            "path {path:?} contains a NUL, newline, carriage return or backslash"
        ));
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(format!(
                "path {path:?} must be relative, with no empty, '.' or '..' components"
            ));
        }
        if component.eq_ignore_ascii_case(".hg") {
            return Err(format!("path {path:?} names Mercurial's own .hg directory"));
        }
    }
    Ok(())
}

/// A path cannot be a file and a directory at once.
fn check_path_conflicts(tree: &BTreeMap<String, Entry>, path: &str) -> Result<(), String> {
    let mut end = 0;
    while let Some(offset) = path[end..].find('/') {
        end += offset;
        let dir = &path[..end];
        if tree.contains_key(dir) {
            return Err(format!(
                "path {path:?} needs {dir:?} to be a directory, but it is a file"
            ));
        }
        end += 1;
    }
    let prefix = format!("{path}/");
    if let Some((other, _)) = tree.range(prefix.clone()..).next() {
        if other.starts_with(&prefix) {
            return Err(format!(
                "path {path:?} is a directory holding {other:?}, so it cannot be a file"
            ));
        }
    }
    Ok(())
}
