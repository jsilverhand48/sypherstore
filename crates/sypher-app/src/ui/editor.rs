//! The add/edit form.
//!
//! Rendered into the same layer surface as the list rather than a second
//! window. On Wayland a new window means a new surface, a new configure
//! handshake and a second keyboard grab to arbitrate; reusing the one surface
//! we already own avoids all of it, and the popup is modal in spirit anyway.
//!
//! ## The unavoidable plaintext copy
//!
//! Everywhere else in Sypherstore, secret material lives in a [`SecureBuf`]:
//! mlocked, zeroized on drop, never in an ordinary allocation. The editor
//! cannot maintain that. `egui::TextEdit` requires `&mut String`, so a secret
//! being *edited* must exist as a plain `String` for as long as the field is
//! on screen.
//!
//! This is a real, deliberate weakening, confined to the editor. It is
//! mitigated rather than solved:
//!
//! - The window is short-lived; the copy exists only while the form is open.
//! - [`Editor`]'s `Drop` zeroizes the strings, so closing the form wipes them
//!   rather than leaving them for the allocator to hand out later.
//! - The value is moved into a `SecureBuf` on save and the `String` is wiped
//!   immediately, so it never reaches the vault layer unprotected.
//!
//! The residual risk is that `String` can reallocate as the user types, and a
//! reallocation leaves the old buffer's contents behind un-wiped. Fixing that
//! properly needs a secret-aware text widget, which is noted as future work.

use uuid::Uuid;
use zeroize::Zeroize;

use sypher_core::model::{SecretMeta, SecretPayload, SecretType};
use sypher_core::secure::SecureBuf;

/// Which field has keyboard focus. Tab and Shift+Tab move between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Value,
    Username,
    Domain,
    Application,
    Tags,
    Notes,
}

impl Field {
    /// Tab order.
    pub const ORDER: [Field; 7] = [
        Field::Name,
        Field::Value,
        Field::Username,
        Field::Domain,
        Field::Application,
        Field::Tags,
        Field::Notes,
    ];
}

/// The form's contents while it is open.
pub struct Editor {
    /// `None` when adding, `Some` when editing an existing secret.
    pub id: Option<Uuid>,
    pub name: String,
    pub secret_type: SecretType,
    /// Plaintext secret. See the module docs for why this is not a
    /// `SecureBuf`.
    pub value: String,
    pub username: String,
    pub domain: String,
    pub application: String,
    /// Comma-separated; split on save.
    pub tags: String,
    pub notes: String,
    /// Preserved so an edit does not reset the creation date.
    created_at: i64,
    pub focus: Field,
    /// Set when the focused field should grab keyboard focus this frame.
    pub focus_dirty: bool,
    pub error: Option<String>,
}

impl Editor {
    /// An empty form for a new secret.
    pub fn new() -> Self {
        Self {
            id: None,
            name: String::new(),
            secret_type: SecretType::Password,
            value: String::new(),
            username: String::new(),
            domain: String::new(),
            application: String::new(),
            tags: String::new(),
            notes: String::new(),
            created_at: sypher_core::model::now_unix(),
            focus: Field::Name,
            focus_dirty: true,
            error: None,
        }
    }

    /// A form populated from an existing secret.
    ///
    /// Takes the decrypted payload, which the caller obtained only after a
    /// fresh assertion.
    pub fn from_existing(meta: &SecretMeta, payload: &SecretPayload) -> Self {
        Self {
            id: Some(meta.id),
            name: meta.name.clone(),
            secret_type: meta.secret_type,
            value: payload
                .value
                .as_str()
                .unwrap_or_default()
                .to_string(),
            username: meta.username.clone(),
            domain: meta.domain.clone(),
            application: meta.application.clone(),
            tags: meta.tags.join(", "),
            notes: payload
                .notes
                .as_ref()
                .and_then(|n| n.as_str().ok())
                .unwrap_or_default()
                .to_string(),
            created_at: meta.created_at,
            focus: Field::Name,
            focus_dirty: true,
            error: None,
        }
    }

    pub fn is_new(&self) -> bool {
        self.id.is_none()
    }

    pub fn title(&self) -> &'static str {
        if self.is_new() {
            "New secret"
        } else {
            "Edit secret"
        }
    }

    /// Moves focus to the next or previous field, wrapping around.
    pub fn cycle_focus(&mut self, backwards: bool) {
        let order = Field::ORDER;
        let current = order.iter().position(|f| *f == self.focus).unwrap_or(0);
        let next = if backwards {
            (current + order.len() - 1) % order.len()
        } else {
            (current + 1) % order.len()
        };
        self.focus = order[next];
        self.focus_dirty = true;
    }

    /// Validates and converts the form into storable values.
    ///
    /// The secret and notes are moved into `SecureBuf`s and the source strings
    /// are wiped, so a successful save leaves no unprotected copy behind.
    pub fn build(&mut self) -> Result<(SecretMeta, SecretPayload), String> {
        let name = self.name.trim().to_string();
        if name.is_empty() {
            return Err("A name is required.".into());
        }
        if self.value.is_empty() {
            return Err("The secret cannot be empty.".into());
        }

        // Normalized so a domain typed as a full URL still matches the
        // browser's hostname later.
        let domain = sypher_core::search::domain::normalize_host(&self.domain).unwrap_or_default();

        let now = sypher_core::model::now_unix();
        let meta = SecretMeta {
            id: self.id.unwrap_or_else(Uuid::new_v4),
            name,
            domain,
            application: self.application.trim().to_string(),
            secret_type: self.secret_type,
            username: self.username.trim().to_string(),
            tags: self
                .tags
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect(),
            created_at: self.created_at,
            updated_at: now,
        };

        let value = SecureBuf::copy_from(self.value.as_bytes());
        self.value.zeroize();

        let notes = if self.notes.trim().is_empty() {
            None
        } else {
            let n = SecureBuf::copy_from(self.notes.as_bytes());
            self.notes.zeroize();
            Some(n)
        };

        Ok((
            meta,
            SecretPayload {
                value,
                notes,
                extra: Vec::new(),
            },
        ))
    }
}

impl Default for Editor {
    fn default() -> Self {
        Self::new()
    }
}

/// Wipes the plaintext fields when the form closes.
///
/// Without this, an abandoned edit would leave the secret in a freed heap
/// allocation for the allocator to hand to the next caller.
impl Drop for Editor {
    fn drop(&mut self) {
        self.value.zeroize();
        self.notes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled() -> Editor {
        let mut e = Editor::new();
        e.name = "  GitHub  ".into();
        e.value = "hunter2".into();
        e.username = " octocat ".into();
        e.domain = "https://www.github.com/login".into();
        e.tags = "work, , dev ,".into();
        e
    }

    #[test]
    fn build_trims_and_normalizes() {
        let mut e = filled();
        let (meta, payload) = e.build().unwrap();

        assert_eq!(meta.name, "GitHub");
        assert_eq!(meta.username, "octocat");
        // A pasted URL must reduce to a bare host or browser matching fails.
        assert_eq!(meta.domain, "github.com");
        assert_eq!(meta.tags, vec!["work", "dev"]);
        assert_eq!(payload.value.as_slice(), b"hunter2");
        assert!(payload.notes.is_none());
    }

    #[test]
    fn build_wipes_the_plaintext_source() {
        let mut e = filled();
        let _ = e.build().unwrap();
        // The String is emptied by zeroize, leaving nothing to recover.
        assert!(
            !e.value.contains("hunter2"),
            "the plaintext survived the save"
        );
    }

    #[test]
    fn a_missing_name_is_rejected() {
        let mut e = Editor::new();
        e.value = "x".into();
        assert!(e.build().unwrap_err().contains("name"));
    }

    #[test]
    fn an_empty_secret_is_rejected() {
        let mut e = Editor::new();
        e.name = "Thing".into();
        assert!(e.build().unwrap_err().contains("empty"));
    }

    #[test]
    fn editing_preserves_id_and_creation_date() {
        let mut meta = SecretMeta::new("Old", SecretType::ApiKey);
        meta.created_at = 12345;
        meta.updated_at = 12345;
        let payload = SecretPayload::new(SecureBuf::copy_from(b"secret"));

        let mut e = Editor::from_existing(&meta, &payload);
        e.name = "New".into();
        let (built, _) = e.build().unwrap();

        assert_eq!(built.id, meta.id, "editing must not reassign the id");
        assert_eq!(built.created_at, 12345, "creation date must be preserved");
        assert!(built.updated_at >= 12345);
        assert_eq!(built.name, "New");
        assert_eq!(built.secret_type, SecretType::ApiKey);
    }

    #[test]
    fn from_existing_round_trips_the_payload() {
        let meta = SecretMeta::new("Thing", SecretType::Password);
        let payload = SecretPayload {
            value: SecureBuf::copy_from(b"s3cr3t"),
            notes: Some(SecureBuf::copy_from(b"a note")),
            extra: Vec::new(),
        };
        let e = Editor::from_existing(&meta, &payload);
        assert_eq!(e.value, "s3cr3t");
        assert_eq!(e.notes, "a note");
        assert!(!e.is_new());
    }

    #[test]
    fn notes_become_part_of_the_payload() {
        let mut e = filled();
        e.notes = "recovery codes in the safe".into();
        let (_, payload) = e.build().unwrap();
        assert_eq!(
            payload.notes.as_ref().unwrap().as_slice(),
            b"recovery codes in the safe"
        );
    }

    #[test]
    fn blank_notes_are_dropped() {
        let mut e = filled();
        e.notes = "   ".into();
        let (_, payload) = e.build().unwrap();
        assert!(payload.notes.is_none());
    }

    #[test]
    fn focus_cycles_and_wraps_in_both_directions() {
        let mut e = Editor::new();
        assert_eq!(e.focus, Field::Name);

        e.cycle_focus(false);
        assert_eq!(e.focus, Field::Value);

        // Wrap forwards off the end.
        e.focus = *Field::ORDER.last().unwrap();
        e.cycle_focus(false);
        assert_eq!(e.focus, Field::Name);

        // And backwards off the start.
        e.cycle_focus(true);
        assert_eq!(e.focus, *Field::ORDER.last().unwrap());
    }

    #[test]
    fn a_new_editor_reports_itself_as_new() {
        let e = Editor::new();
        assert!(e.is_new());
        assert_eq!(e.title(), "New secret");
    }
}
