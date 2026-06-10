//! Tray menu construction and management

use anyhow::Result;
use tray_icon::menu::{Menu, MenuId, MenuItem, PredefinedMenuItem};

/// Menu item references for event handling
pub struct MenuItems {
    pub status: MenuItem,
    pub scan: MenuItem,
    pub view_alerts: MenuItem,
    pub view_logs: MenuItem,
    pub settings: MenuItem,
    pub about: MenuItem,
    pub exit: MenuItem,
}

/// Menu item IDs
pub struct MenuIds {
    pub status: MenuId,
    pub scan: MenuId,
    pub view_alerts: MenuId,
    pub view_logs: MenuId,
    pub settings: MenuId,
    pub about: MenuId,
    pub exit: MenuId,
}

/// Build the tray context menu
pub fn build_menu(status_text: &str) -> Result<(Menu, MenuItems, MenuIds)> {
    let menu = Menu::new();

    // Status item (disabled, shows current state)
    let status_item = MenuItem::new(status_text, false, None);
    menu.append(&status_item)?;

    menu.append(&PredefinedMenuItem::separator())?;

    // Actions
    let scan_item = MenuItem::new("Run Scan...", true, None);
    menu.append(&scan_item)?;

    let alerts_item = MenuItem::new("View Alerts", true, None);
    menu.append(&alerts_item)?;

    let logs_item = MenuItem::new("View Logs", true, None);
    menu.append(&logs_item)?;

    menu.append(&PredefinedMenuItem::separator())?;

    // Settings
    let settings_item = MenuItem::new("Settings...", true, None);
    menu.append(&settings_item)?;

    let about_item = MenuItem::new("About", true, None);
    menu.append(&about_item)?;

    menu.append(&PredefinedMenuItem::separator())?;

    // Exit
    let exit_item = MenuItem::new("Exit", true, None);
    menu.append(&exit_item)?;

    // Collect IDs from items
    let ids = MenuIds {
        status: status_item.id().clone(),
        scan: scan_item.id().clone(),
        view_alerts: alerts_item.id().clone(),
        view_logs: logs_item.id().clone(),
        settings: settings_item.id().clone(),
        about: about_item.id().clone(),
        exit: exit_item.id().clone(),
    };

    let items = MenuItems {
        status: status_item,
        scan: scan_item,
        view_alerts: alerts_item,
        view_logs: logs_item,
        settings: settings_item,
        about: about_item,
        exit: exit_item,
    };

    Ok((menu, items, ids))
}

/// Update status text in menu
pub fn update_status_text(_menu: &Menu, _status_id: &MenuId, _new_text: &str) -> Result<()> {
    // Note: tray_icon doesn't support updating text directly
    // Would need to rebuild the menu or use a different approach
    Ok(())
}
