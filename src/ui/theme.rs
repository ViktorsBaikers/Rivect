//! Terminal palette (standards §7.3, TD-15). One resolver reads the
//! environment and the stdout TTY state; the renderer paints the status line,
//! dock, composer and modal border from it. Only the indexed terminal colors
//! are used: the terminal's own palette controls the actual RGB, so the
//! resolver makes no truecolor/16-tier claim. Body rows stay `Reset`; accents
//! are painted only when a theme was selected.

use ratatui::style::{Color, Modifier, Style};
use std::ffi::OsString;
use std::io::IsTerminal;
use std::sync::LazyLock;

/// The one stderr note an unknown `RIVECT_THEME` earns, naming the accepted
/// values. The raw value is not echoed: an environment string is untrusted
/// and could carry terminal control bytes.
const UNKNOWN_THEME_NOTE: &str =
    "rivect: unknown RIVECT_THEME; accepted values are light|dark|high-contrast; no theme applied";

/// What the terminal can show (standards §7.3). Only two outcomes exist:
/// mono, or the indexed terminal palette. The 16 colors travel as SGR
/// `38;5;n`/`48;5;n`; no direct-color tier is claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Mono,
    Indexed,
}

/// The three inherited themes (design brief). The selection is explicit
/// except for the `COLORFGBG` background heuristic; there is no universal
/// terminal-theme query. No selection is mono.
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
    theme: Option<Theme>,
}

impl Palette {
    /// The process palette: environment plus `stdout` TTY state, resolved
    /// once. An unknown `RIVECT_THEME` falls back to mono and writes one
    /// stderr note naming the accepted values before the alternate screen is
    /// entered by the caller.
    #[must_use]
    pub fn resolve() -> Self {
        static CACHED: LazyLock<Palette> = LazyLock::new(|| {
            Palette::resolve_reporting(
                &|name| std::env::var_os(name),
                std::io::stdout().is_terminal(),
                &mut std::io::stderr(),
            )
        });
        *CACHED
    }

    /// Resolves and writes the unknown-theme note to `sink`. [`Palette::resolve`]
    /// is this function over stderr; the review entry can therefore announce the
    /// palette before it enters the alternate screen, and a unit test can prove
    /// the note precedes that escape.
    pub(crate) fn resolve_reporting(
        env: &dyn Fn(&str) -> Option<OsString>,
        stdout_tty: bool,
        sink: &mut dyn std::io::Write,
    ) -> Self {
        let (palette, note) = Self::from_sources(env, stdout_tty);
        if let Some(note) = note {
            // A closed sink cannot take the note; the palette still resolves.
            drop(writeln!(sink, "{note}"));
        }
        palette
    }

    /// The pure resolver behind [`Palette::resolve`], with the environment and
    /// TTY state injected so both sources stay unit-testable. `None` is the
    /// mono palette: no valid theme was selected.
    fn from_sources(
        env: &dyn Fn(&str) -> Option<OsString>,
        stdout_tty: bool,
    ) -> (Self, Option<String>) {
        let (theme, note) = resolve_theme(env);
        let term = env("TERM")
            .and_then(|term| term.into_string().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        // NO_COLOR is a presence switch, not a value: any value (even an
        // empty or non-UTF-8 one) turns color off.
        let mono = !stdout_tty
            || env("NO_COLOR").is_some()
            || term.eq_ignore_ascii_case("dumb")
            || theme.is_none();
        let capability = if mono {
            Capability::Mono
        } else {
            Capability::Indexed
        };
        (Self { capability, theme }, note)
    }

    /// The terminal's resolved color capability.
    #[must_use]
    pub fn capability(self) -> Capability {
        self.capability
    }

    /// The selected theme; `None` is the mono default when no valid
    /// `RIVECT_THEME`/`COLORFGBG` selected one.
    #[must_use]
    pub fn theme(self) -> Option<Theme> {
        self.theme
    }

    /// The status line.
    #[must_use]
    pub fn status(self) -> Style {
        self.accent(Token::Status)
    }

    /// The dock's task rows and its economy row: body text.
    #[must_use]
    pub fn dock(self) -> Style {
        self.body()
    }

    /// The composer row.
    #[must_use]
    pub fn composer(self) -> Style {
        self.accent(Token::Composer)
    }

    /// The modal frame's border.
    #[must_use]
    pub fn modal(self) -> Style {
        self.accent(Token::Modal)
    }

    /// The transcript body, painted by the fullscreen region and the inline
    /// insertion from this same style.
    #[must_use]
    pub fn transcript(self) -> Style {
        self.body()
    }

    fn accent(self, token: Token) -> Style {
        let Some(theme) = self.theme else {
            return self.body();
        };
        if self.capability == Capability::Mono {
            return self.body();
        }
        let (color, bold) = match (theme, token) {
            // Contrast-safe on the assumed xterm base: light accents clear
            // 4.5:1 text and 3:1 non-text on white; dark accents clear both
            // on black. Red is reserved for errors, never a palette accent.
            (Theme::Light, Token::Status | Token::Modal) => (Color::Blue, false),
            (Theme::Light, Token::Composer) => (Color::Magenta, false),
            (Theme::Dark, Token::Status | Token::Modal) => (Color::Cyan, false),
            // The standard magenta is 4.48:1 on black; the bright index
            // clears 4.5:1 without leaving the magenta family.
            (Theme::Dark, Token::Composer) => (Color::LightMagenta, false),
            (Theme::HighContrast, Token::Status) => (Color::LightYellow, true),
            (Theme::HighContrast, Token::Composer) => (Color::LightCyan, true),
            (Theme::HighContrast, Token::Modal) => (Color::White, true),
        };
        let style = Style::default().fg(color);
        if bold {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        }
    }

    /// Body rows keep the terminal's own foreground (`Reset`), so a themed
    /// palette never recolors the transcript or dock. High contrast adds bold
    /// even to the body, which mono resolutions keep (bold is not color).
    fn body(self) -> Style {
        let style = Style::default().fg(Color::Reset);
        if self.theme == Some(Theme::HighContrast) {
            style.add_modifier(Modifier::BOLD)
        } else {
            style
        }
    }
}

#[derive(Clone, Copy)]
enum Token {
    Status,
    Composer,
    Modal,
}

/// `RIVECT_THEME` wins; else the `COLORFGBG` background; else no theme (mono).
/// An unknown `RIVECT_THEME` yields no theme plus the one note; a malformed
/// `COLORFGBG` yields no theme silently. A non-UTF-8 value is not ignored:
/// `RIVECT_THEME` is treated as unknown, `NO_COLOR` is still present.
fn resolve_theme(env: &dyn Fn(&str) -> Option<OsString>) -> (Option<Theme>, Option<String>) {
    if let Some(raw) = env("RIVECT_THEME") {
        return match raw.to_str().and_then(Theme::parse) {
            Some(theme) => (Some(theme), None),
            None => (None, Some(UNKNOWN_THEME_NOTE.to_string())),
        };
    }
    let Some(background) = env("COLORFGBG")
        .and_then(|raw| raw.into_string().ok())
        .and_then(|raw| raw.rsplit(';').next().map(str::to_string))
        .and_then(|background| background.parse::<u8>().ok())
        .filter(|background| *background < 16)
    else {
        return (None, None);
    };
    (Some(Theme::from_background(background)), None)
}

#[cfg(test)]
mod tests {
    use super::{Capability, Palette, Theme};
    use ratatui::style::{Color, Modifier, Style};
    use std::ffi::OsString;

    fn resolve(pairs: &[(&str, &str)]) -> (Palette, Option<String>) {
        Palette::from_sources(
            &|name| {
                pairs
                    .iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| OsString::from(value))
            },
            true,
        )
    }

    fn with(theme: Theme) -> Palette {
        Palette {
            capability: Capability::Indexed,
            theme: Some(theme),
        }
    }

    fn mono() -> Palette {
        Palette {
            capability: Capability::Mono,
            theme: None,
        }
    }

    /// The assumed base palette for contrast math: the xterm 16-color
    /// defaults (index 0–15), with a white light background and a black dark
    /// background. The terminal's palette controls the actual RGB; these are
    /// the documented reference values the tokens must clear.
    const XTERM: [((u8, u8, u8), Color); 16] = [
        ((0x00, 0x00, 0x00), Color::Black),
        ((0xcd, 0x00, 0x00), Color::Red),
        ((0x00, 0xcd, 0x00), Color::Green),
        ((0xcd, 0xcd, 0x00), Color::Yellow),
        ((0x00, 0x00, 0xee), Color::Blue),
        ((0xcd, 0x00, 0xcd), Color::Magenta),
        ((0x00, 0xcd, 0xcd), Color::Cyan),
        ((0xe5, 0xe5, 0xe5), Color::Gray),
        ((0x7f, 0x7f, 0x7f), Color::DarkGray),
        ((0xff, 0x00, 0x00), Color::LightRed),
        ((0x00, 0xff, 0x00), Color::LightGreen),
        ((0xff, 0xff, 0x00), Color::LightYellow),
        ((0x5c, 0x5c, 0xff), Color::LightBlue),
        ((0xff, 0x00, 0xff), Color::LightMagenta),
        ((0x00, 0xff, 0xff), Color::LightCyan),
        ((0xff, 0xff, 0xff), Color::White),
    ];
    const LIGHT_BG: (u8, u8, u8) = (0xff, 0xff, 0xff);
    const DARK_BG: (u8, u8, u8) = (0x00, 0x00, 0x00);

    fn rgb(color: Color) -> (u8, u8, u8) {
        XTERM
            .iter()
            .find(|(_, named)| *named == color)
            .map(|(rgb, _)| *rgb)
            .expect("a token uses an indexed xterm color")
    }

    fn channel(value: u8) -> f64 {
        let value = f64::from(value) / 255.0;
        if value <= 0.039_28 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    }

    fn luminance(rgb: (u8, u8, u8)) -> f64 {
        0.2126 * channel(rgb.0) + 0.7152 * channel(rgb.1) + 0.0722 * channel(rgb.2)
    }

    fn contrast(a: (u8, u8, u8), b: (u8, u8, u8)) -> f64 {
        let (a, b) = (luminance(a), luminance(b));
        let (high, low) = if a > b { (a, b) } else { (b, a) };
        (high + 0.05) / (low + 0.05)
    }

    fn fg(style: Style) -> Color {
        style.fg.expect("a painted style carries a foreground")
    }

    fn is_bold(style: Style) -> bool {
        style.add_modifier.contains(Modifier::BOLD)
    }

    #[test]
    fn absent_or_malformed_sources_resolve_to_mono() {
        for pairs in [
            vec![],
            vec![("COLORFGBG", "")],
            vec![("COLORFGBG", "garbage")],
            vec![("COLORFGBG", "fg;bg")],
            vec![("COLORFGBG", "300;999")],
            vec![("COLORFGBG", "0;16")],
            vec![("COLORFGBG", "0;255")],
        ] {
            let (palette, note) = resolve(&pairs);
            assert_eq!(palette.capability(), Capability::Mono, "{pairs:?}");
            assert_eq!(palette.theme(), None, "{pairs:?}");
            assert_eq!(note, None, "{pairs:?}");
        }
        let (palette, _) = resolve(&[("COLORTERM", "truecolor")]);
        assert_eq!(palette.capability(), Capability::Mono);
        assert_eq!(palette.theme(), None);
    }

    #[test]
    fn colorfgbg_background_field_selects_light_and_dark() {
        assert_eq!(
            resolve(&[("COLORFGBG", "0;15")]).0.theme(),
            Some(Theme::Light)
        );
        assert_eq!(
            resolve(&[("COLORFGBG", "15;0")]).0.theme(),
            Some(Theme::Dark)
        );
        // Only the last field is the background; a foreground that looks
        // light does not decide.
        assert_eq!(
            resolve(&[("COLORFGBG", "15;0;0")]).0.theme(),
            Some(Theme::Dark)
        );
        assert_eq!(
            resolve(&[("COLORFGBG", "0;15;8")]).0.theme(),
            Some(Theme::Light)
        );
        assert_eq!(resolve(&[("COLORFGBG", "7")]).0.theme(), Some(Theme::Dark));
        assert_eq!(resolve(&[("COLORFGBG", "8")]).0.theme(), Some(Theme::Light));
    }

    #[test]
    fn rivect_theme_wins_over_colorfgbg_and_names_its_values() {
        assert_eq!(
            resolve(&[("COLORFGBG", "15;0"), ("RIVECT_THEME", "light")])
                .0
                .theme(),
            Some(Theme::Light)
        );
        assert_eq!(
            resolve(&[("COLORFGBG", "0;15"), ("RIVECT_THEME", "high-contrast")])
                .0
                .theme(),
            Some(Theme::HighContrast)
        );
        assert_eq!(
            resolve(&[("COLORFGBG", "0;15"), ("RIVECT_THEME", "dark")])
                .0
                .theme(),
            Some(Theme::Dark)
        );
    }

    #[test]
    fn unknown_rivect_theme_falls_back_to_mono_with_one_note() {
        let (palette, note) = resolve(&[("COLORFGBG", "0;15"), ("RIVECT_THEME", "sepia")]);
        assert_eq!(palette.theme(), None);
        assert_eq!(palette.capability(), Capability::Mono);
        let note = note.expect("an unknown value names its accepted values");
        assert!(note.contains("light|dark|high-contrast"), "{note}");
        assert!(note.starts_with("rivect: unknown RIVECT_THEME"), "{note}");
        // The untrusted value is never echoed into the note.
        assert!(!note.contains("sepia"), "{note}");
        assert_eq!(resolve(&[("RIVECT_THEME", "light")]).1, None);
    }

    #[test]
    fn mono_sources_force_mono_whatever_theme_was_selected() {
        for pairs in [
            vec![("RIVECT_THEME", "light")],
            vec![("TERM", "xterm-256color"), ("RIVECT_THEME", "dark")],
        ] {
            let mut all = pairs.clone();
            all.push(("NO_COLOR", ""));
            let (palette, _) = resolve(&all);
            assert_eq!(palette.capability(), Capability::Mono, "{pairs:?}");
            for style in [palette.status(), palette.composer(), palette.modal()] {
                assert_eq!(fg(style), Color::Reset);
            }
        }
        let (palette, _) = resolve(&[("RIVECT_THEME", "dark"), ("TERM", "dumb")]);
        assert_eq!(palette.capability(), Capability::Mono);
        let (palette, _) =
            Palette::from_sources(&|_| Some(OsString::from("xterm-256color")), false);
        assert_eq!(palette.capability(), Capability::Mono);
    }

    #[test]
    fn a_selected_theme_is_indexed_and_mono_is_the_default() {
        let (palette, _) = resolve(&[("COLORFGBG", "15;0"), ("TERM", "xterm-256color")]);
        assert_eq!(palette.capability(), Capability::Indexed);
        assert_eq!(palette.theme(), Some(Theme::Dark));
        assert_eq!(mono().capability(), Capability::Mono);
        // tmux/screen never receive OSC/truecolor: the palette emits only
        // indexed foreground selections, whatever the terminal claims.
        for term in ["tmux-256color", "screen-256color", "xterm-direct"] {
            let (palette, _) = resolve(&[
                ("RIVECT_THEME", "dark"),
                ("TERM", term),
                ("COLORTERM", "truecolor"),
            ]);
            assert_eq!(palette.capability(), Capability::Indexed, "{term}");
        }
    }

    #[test]
    fn accent_tokens_clear_non_text_and_text_contrast() {
        let light = with(Theme::Light);
        assert!(contrast(rgb(fg(light.status())), LIGHT_BG) >= 4.5);
        assert!(contrast(rgb(fg(light.composer())), LIGHT_BG) >= 4.5);
        assert!(contrast(rgb(fg(light.modal())), LIGHT_BG) >= 3.0);
        let dark = with(Theme::Dark);
        assert!(contrast(rgb(fg(dark.status())), DARK_BG) >= 4.5);
        assert!(contrast(rgb(fg(dark.composer())), DARK_BG) >= 4.5);
        assert!(contrast(rgb(fg(dark.modal())), DARK_BG) >= 3.0);
        let high = with(Theme::HighContrast);
        assert!(contrast(rgb(fg(high.status())), DARK_BG) >= 4.5);
        assert!(contrast(rgb(fg(high.composer())), DARK_BG) >= 4.5);
        assert!(contrast(rgb(fg(high.modal())), DARK_BG) >= 3.0);
        // Red is reserved for errors; no accent uses it.
        for palette in [light, dark, high] {
            for style in [palette.status(), palette.composer(), palette.modal()] {
                assert!(!matches!(fg(style), Color::Red | Color::LightRed));
            }
        }
    }

    #[test]
    fn palettes_are_distinct_and_high_contrast_is_bold() {
        let light = with(Theme::Light);
        let dark = with(Theme::Dark);
        let high = with(Theme::HighContrast);
        for (light, dark, high) in [
            (light.status(), dark.status(), high.status()),
            (light.composer(), dark.composer(), high.composer()),
            (light.modal(), dark.modal(), high.modal()),
        ] {
            assert_ne!(light, dark);
            assert_ne!(light, high);
            assert_ne!(dark, high);
        }
        for style in [
            high.status(),
            high.composer(),
            high.modal(),
            high.dock(),
            high.transcript(),
        ] {
            assert!(is_bold(style));
        }
        for palette in [light, dark, mono()] {
            for style in [palette.status(), palette.composer(), palette.modal()] {
                assert!(!is_bold(style));
            }
        }
    }

    #[test]
    fn body_rows_are_reset_and_mono_has_no_color() {
        for palette in [
            with(Theme::Light),
            with(Theme::Dark),
            with(Theme::HighContrast),
        ] {
            for style in [palette.dock(), palette.transcript()] {
                assert_eq!(fg(style), Color::Reset);
            }
        }
        for style in [
            mono().status(),
            mono().composer(),
            mono().modal(),
            mono().dock(),
        ] {
            assert_eq!(fg(style), Color::Reset);
        }
    }

    /// Standards §7.3 names the basic-16 fallback; the accepted representation
    /// is the indexed `38;5;n` form for n 0–15. No token may be RGB or a
    /// 256-color index, and the palette never emits OSC/truecolor.
    #[test]
    fn tokens_stay_inside_the_indexed_16_color_fallback() {
        const NAMED: [Color; 16] = [
            Color::Black,
            Color::Red,
            Color::Green,
            Color::Yellow,
            Color::Blue,
            Color::Magenta,
            Color::Cyan,
            Color::Gray,
            Color::DarkGray,
            Color::LightRed,
            Color::LightGreen,
            Color::LightYellow,
            Color::LightBlue,
            Color::LightMagenta,
            Color::LightCyan,
            Color::White,
        ];
        for palette in [
            with(Theme::Light),
            with(Theme::Dark),
            with(Theme::HighContrast),
        ] {
            for style in [
                palette.status(),
                palette.composer(),
                palette.modal(),
                palette.dock(),
                palette.transcript(),
            ] {
                let color = fg(style);
                assert!(
                    color == Color::Reset || NAMED.contains(&color),
                    "{color:?} is outside the indexed 16-color fallback"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_values_are_not_silently_ignored() {
        use std::os::unix::ffi::OsStringExt as _;
        let bad = || OsString::from_vec(vec![0xff, 0xfe]);
        let (palette, note) = Palette::from_sources(
            &|name| match name {
                "NO_COLOR" => Some(bad()),
                "RIVECT_THEME" => None,
                _ => None,
            },
            true,
        );
        assert_eq!(palette.capability(), Capability::Mono);
        assert_eq!(note, None);
        let (palette, note) = Palette::from_sources(
            &|name| match name {
                "RIVECT_THEME" => Some(bad()),
                _ => None,
            },
            true,
        );
        assert_eq!(palette.capability(), Capability::Mono);
        assert!(
            note.is_some(),
            "a non-UTF-8 RIVECT_THEME is an unknown value"
        );
    }
}
