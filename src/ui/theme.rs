//! Terminal color capability and the three inherited themes (standards §7.3,
//! TD-15). One resolver reads the environment and the stdout TTY state; the
//! renderer paints the status line, dock, composer and modal border from it.
//! Mono resolutions carry no color, only the high-contrast palette's bold.

use ratatui::style::{Color, Modifier, Style};
use std::io::{IsTerminal, Write as _};
use std::sync::LazyLock;

/// The one stderr note an unknown `RIVECT_THEME` earns, naming the accepted
/// values. The raw value is not echoed: an environment string is untrusted
/// and could carry terminal control bytes.
const UNKNOWN_THEME_NOTE: &str =
    "rivect: unknown RIVECT_THEME; accepted values are light|dark|high-contrast; using dark";

/// What the terminal can show (standards §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// No color at all: `NO_COLOR`, `TERM=dumb`, or a non-TTY stdout.
    Mono,
    /// The 16 ANSI colors.
    Ansi16,
    /// The 256-color cube.
    Ansi256,
    /// 24-bit direct color.
    Truecolor,
}

/// The three inherited themes (design brief). The selection is explicit
/// except for the `COLORFGBG` background heuristic; there is no universal
/// terminal-theme query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    Light,
    Dark,
    HighContrast,
}

impl Theme {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            "high-contrast" => Some(Self::HighContrast),
            _ => None,
        }
    }

    /// The standard `COLORFGBG` split: an index below eight is a dark
    /// background, eight and above a light one.
    fn from_background(index: u8) -> Self {
        if index < 8 { Self::Dark } else { Self::Light }
    }
}

/// The resolved palette. Every render surface reads its one style from here,
/// so the capability and theme are decided once per process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    capability: Capability,
    theme: Theme,
}

impl Palette {
    /// The process palette: environment plus `stdout` TTY state, resolved
    /// once. An unknown `RIVECT_THEME` falls back to dark and writes one
    /// stderr note naming the accepted values.
    #[must_use]
    pub fn resolve() -> Self {
        static CACHED: LazyLock<Palette> = LazyLock::new(|| {
            let (palette, note) = Palette::from_sources(
                &|name| std::env::var(name).ok(),
                std::io::stdout().is_terminal(),
            );
            if let Some(note) = note {
                // A closed stderr cannot take the note; the palette still resolves.
                drop(writeln!(std::io::stderr(), "{note}"));
            }
            palette
        });
        *CACHED
    }

    /// The pure resolver behind [`Palette::resolve`], with the environment and
    /// TTY state injected so both sources stay unit-testable.
    fn from_sources(
        env: &dyn Fn(&str) -> Option<String>,
        stdout_tty: bool,
    ) -> (Self, Option<String>) {
        let (theme, note) = resolve_theme(env);
        let term = env("TERM").unwrap_or_default();
        let term = term.to_ascii_lowercase();
        let mono = !stdout_tty || env("NO_COLOR").is_some() || term.eq_ignore_ascii_case("dumb");
        let capability = if mono {
            Capability::Mono
        } else {
            resolve_capability(env, &term)
        };
        (Self { capability, theme }, note)
    }

    /// The terminal's resolved color capability.
    #[must_use]
    pub fn capability(self) -> Capability {
        self.capability
    }

    /// The selected theme after the `RIVECT_THEME`/`COLORFGBG` precedence.
    #[must_use]
    pub fn theme(self) -> Theme {
        self.theme
    }

    /// The status line.
    #[must_use]
    pub fn status(self) -> Style {
        self.paint(self.status_color())
    }

    /// The dock's task rows and its economy row.
    #[must_use]
    pub fn dock(self) -> Style {
        self.paint(self.dock_color())
    }

    /// The composer row.
    #[must_use]
    pub fn composer(self) -> Style {
        self.paint(self.composer_color())
    }

    /// The modal frame's border.
    #[must_use]
    pub fn modal(self) -> Style {
        self.paint(self.modal_color())
    }

    /// The transcript body, painted by the fullscreen region and the inline
    /// insertion from this same style.
    #[must_use]
    pub fn transcript(self) -> Style {
        self.paint(self.transcript_color())
    }

    fn paint(self, color: Color) -> Style {
        let style = match self.capability {
            Capability::Mono => Style::default(),
            Capability::Ansi16 | Capability::Ansi256 | Capability::Truecolor => {
                Style::default().fg(color)
            }
        };
        if self.theme == Theme::HighContrast {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        }
    }

    // The four surfaces carry distinct colors inside a theme, so every
    // carrier reads on its own; across themes each surface changes, which is
    // what the installed matrix fingerprints.
    fn status_color(self) -> Color {
        match self.theme {
            Theme::Light => Color::Blue,
            Theme::Dark => Color::Cyan,
            Theme::HighContrast => Color::Yellow,
        }
    }

    fn dock_color(self) -> Color {
        match self.theme {
            Theme::Light => Color::Black,
            Theme::Dark => Color::White,
            Theme::HighContrast => Color::White,
        }
    }

    fn composer_color(self) -> Color {
        match self.theme {
            Theme::Light => Color::Magenta,
            Theme::Dark => Color::Green,
            Theme::HighContrast => Color::Red,
        }
    }

    fn modal_color(self) -> Color {
        match self.theme {
            Theme::Light => Color::Cyan,
            Theme::Dark => Color::Blue,
            Theme::HighContrast => Color::Red,
        }
    }

    fn transcript_color(self) -> Color {
        match self.theme {
            Theme::Light => Color::Black,
            Theme::Dark => Color::White,
            Theme::HighContrast => Color::White,
        }
    }
}

/// `RIVECT_THEME` wins; else the `COLORFGBG` background; else dark. The note
/// is the unknown-value diagnostic, at most one per resolution.
fn resolve_theme(env: &dyn Fn(&str) -> Option<String>) -> (Theme, Option<String>) {
    if let Some(raw) = env("RIVECT_THEME") {
        return match Theme::parse(&raw) {
            Some(theme) => (theme, None),
            None => (Theme::Dark, Some(UNKNOWN_THEME_NOTE.to_string())),
        };
    }
    let theme = env("COLORFGBG")
        .and_then(|raw| raw.rsplit(';').next().map(str::to_string))
        .and_then(|background| background.parse::<u8>().ok())
        .map_or(Theme::Dark, Theme::from_background);
    (theme, None)
}

/// Standards §7.3 capability precedence. A tmux/screen terminal never gets
/// truecolor even when `COLORTERM` claims it.
fn resolve_capability(env: &dyn Fn(&str) -> Option<String>, term: &str) -> Capability {
    let tmux_like = term.starts_with("tmux") || term.starts_with("screen");
    if tmux_like {
        return if term.ends_with("-256color") {
            Capability::Ansi256
        } else {
            Capability::Ansi16
        };
    }
    let truecolor = env("COLORTERM")
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "truecolor" | "24bit"))
        || term.ends_with("-direct");
    if truecolor {
        Capability::Truecolor
    } else if term.ends_with("-256color") {
        Capability::Ansi256
    } else {
        Capability::Ansi16
    }
}

#[cfg(test)]
mod tests {
    use super::{Capability, Palette, Theme};

    fn resolve(pairs: &[(&str, &str)]) -> (Palette, Option<String>) {
        Palette::from_sources(
            &|name| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| (*value).to_string())
            },
            true,
        )
    }

    fn with(theme: Theme) -> Palette {
        Palette {
            capability: Capability::Ansi256,
            theme,
        }
    }

    #[test]
    fn colorfgbg_background_field_selects_light_and_dark() {
        assert_eq!(resolve(&[("COLORFGBG", "0;15")]).0.theme(), Theme::Light);
        assert_eq!(resolve(&[("COLORFGBG", "15;0")]).0.theme(), Theme::Dark);
        // Only the last field is the background; a foreground that looks
        // light does not decide.
        assert_eq!(resolve(&[("COLORFGBG", "15;0;0")]).0.theme(), Theme::Dark);
        assert_eq!(resolve(&[("COLORFGBG", "0;15;8")]).0.theme(), Theme::Light);
        assert_eq!(resolve(&[("COLORFGBG", "7")]).0.theme(), Theme::Dark);
    }

    #[test]
    fn malformed_or_absent_colorfgbg_falls_back_to_dark() {
        for pairs in [
            vec![],
            vec![("COLORFGBG", "")],
            vec![("COLORFGBG", "garbage")],
            vec![("COLORFGBG", "fg;bg")],
            vec![("COLORFGBG", "300;999")],
        ] {
            assert_eq!(resolve(&pairs).0.theme(), Theme::Dark, "{pairs:?}");
        }
    }

    #[test]
    fn rivect_theme_wins_over_colorfgbg_and_names_its_values() {
        assert_eq!(
            resolve(&[("COLORFGBG", "15;0"), ("RIVECT_THEME", "light")])
                .0
                .theme(),
            Theme::Light
        );
        assert_eq!(
            resolve(&[("COLORFGBG", "0;15"), ("RIVECT_THEME", "high-contrast")])
                .0
                .theme(),
            Theme::HighContrast
        );
        assert_eq!(
            resolve(&[("COLORFGBG", "0;15"), ("RIVECT_THEME", "dark")])
                .0
                .theme(),
            Theme::Dark
        );
    }

    #[test]
    fn unknown_rivect_theme_falls_back_to_dark_with_one_note() {
        let (palette, note) = resolve(&[("COLORFGBG", "0;15"), ("RIVECT_THEME", "sepia")]);
        assert_eq!(palette.theme(), Theme::Dark);
        let note = note.expect("an unknown value names its accepted values");
        assert!(note.contains("light|dark|high-contrast"), "{note}");
        assert!(note.starts_with("rivect: unknown RIVECT_THEME"), "{note}");
        // The untrusted value is never echoed into the note.
        assert!(!note.contains("sepia"), "{note}");
        assert_eq!(resolve(&[("RIVECT_THEME", "light")]).1, None);
    }

    #[test]
    fn mono_sources_force_mono_whatever_the_terminal_claims() {
        for pairs in [
            vec![("COLORTERM", "truecolor")],
            vec![("TERM", "xterm-direct")],
            vec![("TERM", "xterm-256color")],
        ] {
            let mut all = pairs.clone();
            all.push(("NO_COLOR", ""));
            assert_eq!(resolve(&all).0.capability(), Capability::Mono, "{pairs:?}");
        }
        let dumb = resolve(&[("TERM", "dumb"), ("COLORTERM", "truecolor")]);
        assert_eq!(dumb.0.capability(), Capability::Mono);
        let non_tty = Palette::from_sources(&|_| Some("xterm-256color".to_string()), false);
        assert_eq!(non_tty.0.capability(), Capability::Mono);
    }

    #[test]
    fn capability_follows_the_standards_precedence() {
        for pairs in [
            vec![("COLORTERM", "truecolor")],
            vec![("COLORTERM", "24bit")],
            vec![("TERM", "xterm-direct")],
        ] {
            assert_eq!(
                resolve(&pairs).0.capability(),
                Capability::Truecolor,
                "{pairs:?}"
            );
        }
        assert_eq!(
            resolve(&[("TERM", "xterm-256color")]).0.capability(),
            Capability::Ansi256
        );
        assert_eq!(
            resolve(&[("TERM", "xterm")]).0.capability(),
            Capability::Ansi16
        );
        // tmux/screen degrade: truecolor is not assumed even when COLORTERM
        // claims it.
        for pairs in [
            vec![("TERM", "tmux-256color"), ("COLORTERM", "truecolor")],
            vec![("TERM", "screen-256color"), ("COLORTERM", "24bit")],
        ] {
            assert_eq!(
                resolve(&pairs).0.capability(),
                Capability::Ansi256,
                "{pairs:?}"
            );
        }
        for pairs in [
            vec![("TERM", "tmux"), ("COLORTERM", "truecolor")],
            vec![("TERM", "screen"), ("COLORTERM", "truecolor")],
            vec![("TERM", "screen-direct")],
        ] {
            assert_eq!(
                resolve(&pairs).0.capability(),
                Capability::Ansi16,
                "{pairs:?}"
            );
        }
    }

    #[test]
    fn palettes_are_pairwise_distinct_per_surface_and_high_contrast_is_bold() {
        let light = with(Theme::Light);
        let dark = with(Theme::Dark);
        let contrast = with(Theme::HighContrast);
        for (light, dark, contrast) in [
            (light.status(), dark.status(), contrast.status()),
            (light.dock(), dark.dock(), contrast.dock()),
            (light.composer(), dark.composer(), contrast.composer()),
            (light.modal(), dark.modal(), contrast.modal()),
            (light.transcript(), dark.transcript(), contrast.transcript()),
        ] {
            assert_ne!(light, dark);
            assert_ne!(light, contrast);
            assert_ne!(dark, contrast);
        }
        for style in [
            contrast.status(),
            contrast.dock(),
            contrast.composer(),
            contrast.modal(),
            contrast.transcript(),
        ] {
            assert!(style.add_modifier.contains(ratatui::style::Modifier::BOLD));
        }
        for style in [
            dark.status(),
            dark.dock(),
            dark.composer(),
            dark.modal(),
            dark.transcript(),
        ] {
            assert!(!style.add_modifier.contains(ratatui::style::Modifier::BOLD));
        }
    }

    #[test]
    fn mono_styles_carry_no_color_and_keep_high_contrast_bold() {
        for theme in [Theme::Light, Theme::Dark] {
            let mono = Palette {
                capability: Capability::Mono,
                theme,
            };
            for style in [
                mono.status(),
                mono.dock(),
                mono.composer(),
                mono.modal(),
                mono.transcript(),
            ] {
                assert_eq!(style.fg, None, "{theme:?}");
                assert_eq!(style.bg, None, "{theme:?}");
            }
        }
        let contrast = Palette {
            capability: Capability::Mono,
            theme: Theme::HighContrast,
        };
        assert_eq!(contrast.status().fg, None);
        assert!(
            contrast
                .status()
                .add_modifier
                .contains(ratatui::style::Modifier::BOLD)
        );
    }
}
