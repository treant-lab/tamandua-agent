// ! Honeyfile Template System - Realistic Deception Content
//!
//! Provides realistic honeyfile templates with embedded canary tokens
//! for advanced threat detection and attacker tracking.
//!
//! Features:
//! - Professional document templates (DOCX, XLSX, PDF)
//! - Credential files with fake but plausible data
//! - SSH keys, VPN configs, crypto wallets
//! - Email archives with sensitive content
//! - Embedded canary tokens for tracking
//! - Template variable substitution
//! - Metadata generation for realism
//!
//! MITRE ATT&CK Detection:
//! - T1552.001 (Credentials In Files)
//! - T1552.004 (Private Keys)
//! - T1555 (Credentials from Password Stores)
//! - T1005 (Data from Local System)

use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Honeyfile template category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemplateCategory {
    /// HR and financial documents
    Documents,
    /// Spreadsheets with financial/customer data
    Spreadsheets,
    /// PDF contracts and legal documents
    Pdfs,
    /// Code configuration files (.env, config.json, etc.)
    Code,
    /// SSH private keys
    SshKeys,
    /// VPN configuration files
    Vpn,
    /// Cryptocurrency wallets
    Crypto,
    /// Email archives
    Email,
}

/// Template variable for substitution
#[derive(Debug, Clone)]
pub struct TemplateVariable {
    pub name: String,
    pub value: String,
}

/// Honeyfile template with embedded canary token
#[derive(Debug, Clone)]
pub struct HoneyfileTemplate {
    pub name: String,
    pub category: TemplateCategory,
    pub file_extension: String,
    pub description: String,
    pub content: Vec<u8>,
    pub canary_token: String,
    pub metadata: HashMap<String, String>,
}

impl HoneyfileTemplate {
    /// Create a new honeyfile template
    pub fn new(
        name: &str,
        category: TemplateCategory,
        file_extension: &str,
        description: &str,
        content: Vec<u8>,
    ) -> Self {
        let canary_token = format!("TAMANDUA-{}", Uuid::new_v4());
        let mut metadata = HashMap::new();

        metadata.insert("created_at".to_string(), chrono::Utc::now().to_rfc3339());
        metadata.insert("template_version".to_string(), "1.0".to_string());
        metadata.insert("canary_token".to_string(), canary_token.clone());

        Self {
            name: name.to_string(),
            category,
            file_extension: file_extension.to_string(),
            description: description.to_string(),
            content,
            canary_token,
            metadata,
        }
    }

    /// Render template with variable substitution
    pub fn render(&self, variables: &[TemplateVariable]) -> Vec<u8> {
        let mut content = self.content.clone();
        let content_str = String::from_utf8_lossy(&content);
        let mut rendered = content_str.to_string();

        // Substitute canary token
        rendered = rendered.replace("{{CANARY_ID}}", &self.canary_token);

        // Substitute custom variables
        for var in variables {
            let placeholder = format!("{{{{{}}}}}", var.name);
            rendered = rendered.replace(&placeholder, &var.value);
        }

        rendered.into_bytes()
    }

    /// Get suggested deployment path
    pub fn deployment_path(&self) -> PathBuf {
        match self.category {
            TemplateCategory::Documents => PathBuf::from("Documents"),
            TemplateCategory::Spreadsheets => PathBuf::from("Documents"),
            TemplateCategory::Pdfs => PathBuf::from("Documents/Contracts"),
            TemplateCategory::Code => PathBuf::from("projects"),
            TemplateCategory::SshKeys => PathBuf::from(".ssh"),
            TemplateCategory::Vpn => PathBuf::from(".openvpn"),
            TemplateCategory::Crypto => PathBuf::from(".ethereum"),
            TemplateCategory::Email => PathBuf::from("Archives"),
        }
    }
}

/// Template manager for loading and managing honeyfile templates
pub struct TemplateManager {
    templates: Vec<HoneyfileTemplate>,
    template_dir: PathBuf,
}

impl TemplateManager {
    /// Create a new template manager
    pub fn new(template_dir: PathBuf) -> Self {
        Self {
            templates: Vec::new(),
            template_dir,
        }
    }

    /// Load all templates from directory
    pub fn load_templates(&mut self) -> Result<()> {
        // STUB — PRODUCTION-GAP (minor), not production. self.template_dir is never read:
        // no files are loaded from disk, so self.templates stays empty unless populated
        // elsewhere. Built-in/server-pushed templates are used instead. Missing:
        // directory scan + parse of priv/honeyfiles into HoneyfileTemplate entries.
        tracing::info!(
            template_dir = %self.template_dir.display(),
            "Template loading from directory not yet implemented - using built-in templates"
        );
        Ok(())
    }

    /// Get template by name
    pub fn get_template(&self, name: &str) -> Option<&HoneyfileTemplate> {
        self.templates.iter().find(|t| t.name == name)
    }

    /// Get all templates in category
    pub fn get_templates_by_category(&self, category: TemplateCategory) -> Vec<&HoneyfileTemplate> {
        self.templates
            .iter()
            .filter(|t| t.category == category)
            .collect()
    }

    /// Deploy a template to a specific path
    pub fn deploy_template(
        &self,
        template_name: &str,
        deployment_path: &Path,
        variables: &[TemplateVariable],
    ) -> Result<PathBuf> {
        let template = self
            .get_template(template_name)
            .ok_or_else(|| anyhow::anyhow!("Template not found: {}", template_name))?;

        let content = template.render(variables);

        // Create parent directory if needed
        if let Some(parent) = deployment_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(deployment_path, content)?;

        tracing::info!(
            template = %template_name,
            path = %deployment_path.display(),
            canary_token = %template.canary_token,
            "Deployed honeyfile template"
        );

        Ok(deployment_path.to_path_buf())
    }

    /// Get recommended honeyfile deployments for a system
    pub fn get_recommended_deployments(&self) -> Vec<(&HoneyfileTemplate, PathBuf)> {
        let home_dir = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));

        self.templates
            .iter()
            .map(|template| {
                let relative_path = template.deployment_path();
                let full_path = home_dir.join(relative_path).join(&template.name);
                (template, full_path)
            })
            .collect()
    }
}

/// Create realistic metadata for honeyfiles
pub fn create_realistic_metadata() -> HashMap<String, String> {
    let mut metadata = HashMap::new();

    metadata.insert("author".to_string(), "HR Department".to_string());
    metadata.insert("company".to_string(), "Company Inc.".to_string());
    metadata.insert("created".to_string(), "2023-11-01T10:00:00Z".to_string());
    metadata.insert("modified".to_string(), chrono::Utc::now().to_rfc3339());
    metadata.insert("classification".to_string(), "Confidential".to_string());

    metadata
}

/// Generate realistic file timestamps (2-8 weeks ago)
pub fn realistic_timestamp() -> std::time::SystemTime {
    let weeks_ago = rand::random::<u64>() % 6 + 2; // 2-8 weeks
    std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(60 * 60 * 24 * 7 * weeks_ago))
        .unwrap_or(std::time::SystemTime::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_creation() {
        let template = HoneyfileTemplate::new(
            "test_doc",
            TemplateCategory::Documents,
            "docx",
            "Test document",
            b"Canary: {{CANARY_ID}}".to_vec(),
        );

        assert_eq!(template.name, "test_doc");
        assert_eq!(template.file_extension, "docx");
        assert!(template.canary_token.starts_with("TAMANDUA-"));
    }

    #[test]
    fn test_template_rendering() {
        let template = HoneyfileTemplate::new(
            "test",
            TemplateCategory::Code,
            "env",
            "Test",
            b"Canary: {{CANARY_ID}}\nCompany: {{COMPANY}}".to_vec(),
        );

        let variables = vec![TemplateVariable {
            name: "COMPANY".to_string(),
            value: "TestCorp".to_string(),
        }];

        let rendered = template.render(&variables);
        let rendered_str = String::from_utf8_lossy(&rendered);

        assert!(rendered_str.contains("TAMANDUA-"));
        assert!(rendered_str.contains("TestCorp"));
    }

    #[test]
    fn test_deployment_path() {
        let template =
            HoneyfileTemplate::new("id_rsa", TemplateCategory::SshKeys, "", "SSH key", vec![]);

        let path = template.deployment_path();
        assert_eq!(path, PathBuf::from(".ssh"));
    }
}
