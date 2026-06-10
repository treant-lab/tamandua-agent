//! Tray icon management

use anyhow::{Context, Result};
use tray_icon::Icon;

/// Load the tray icon
pub fn load_icon() -> Result<Icon> {
    // Load embedded icon or use default
    #[cfg(target_os = "windows")]
    {
        load_windows_icon()
    }

    #[cfg(target_os = "linux")]
    {
        load_linux_icon()
    }

    #[cfg(target_os = "macos")]
    {
        load_macos_icon()
    }
}

#[cfg(target_os = "windows")]
fn load_windows_icon() -> Result<Icon> {
    // Try to load from embedded resource
    // For now, use a simple generated icon
    let rgba = generate_default_icon_rgba();
    Icon::from_rgba(rgba, 32, 32).context("Failed to create icon from RGBA")
}

#[cfg(target_os = "linux")]
fn load_linux_icon() -> Result<Icon> {
    let rgba = generate_default_icon_rgba();
    Icon::from_rgba(rgba, 32, 32).context("Failed to create icon from RGBA")
}

#[cfg(target_os = "macos")]
fn load_macos_icon() -> Result<Icon> {
    let rgba = generate_default_icon_rgba();
    Icon::from_rgba(rgba, 32, 32).context("Failed to create icon from RGBA")
}

/// Generate a default icon (32x32 RGBA)
fn generate_default_icon_rgba() -> Vec<u8> {
    let size = 32;
    let mut rgba = Vec::with_capacity(size * size * 4);

    for y in 0..size {
        for x in 0..size {
            // Create a simple shield icon
            let in_circle = {
                let dx = x as f32 - 16.0;
                let dy = y as f32 - 16.0;
                (dx * dx + dy * dy).sqrt() < 14.0
            };

            if in_circle {
                // Green shield (active/protected)
                rgba.extend_from_slice(&[0, 180, 0, 255]); // Green
            } else {
                // Transparent background
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }

    rgba
}

/// Generate warning icon (yellow)
#[allow(dead_code)]
pub fn generate_warning_icon_rgba() -> Vec<u8> {
    let size = 32;
    let mut rgba = Vec::with_capacity(size * size * 4);

    for y in 0..size {
        for x in 0..size {
            let in_circle = {
                let dx = x as f32 - 16.0;
                let dy = y as f32 - 16.0;
                (dx * dx + dy * dy).sqrt() < 14.0
            };

            if in_circle {
                rgba.extend_from_slice(&[255, 200, 0, 255]); // Yellow
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }

    rgba
}

/// Generate error icon (red)
#[allow(dead_code)]
pub fn generate_error_icon_rgba() -> Vec<u8> {
    let size = 32;
    let mut rgba = Vec::with_capacity(size * size * 4);

    for y in 0..size {
        for x in 0..size {
            let in_circle = {
                let dx = x as f32 - 16.0;
                let dy = y as f32 - 16.0;
                (dx * dx + dy * dy).sqrt() < 14.0
            };

            if in_circle {
                rgba.extend_from_slice(&[220, 0, 0, 255]); // Red
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }

    rgba
}
