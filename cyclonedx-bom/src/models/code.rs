/*
 * This file is part of CycloneDX Rust Cargo.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::{
    external_models::{date_time::DateTime, normalized_string::NormalizedString, uri::Uri},
    validation::{Validate, ValidationContext, ValidationPathComponent, ValidationResult},
};

use super::attached_text::AttachedText;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub uid: Option<NormalizedString>,
    pub url: Option<Uri>,
    pub author: Option<IdentifiableAction>,
    pub committer: Option<IdentifiableAction>,
    pub message: Option<NormalizedString>,
}

impl Validate for Commit {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut results: Vec<ValidationResult> = vec![];

        if let Some(uid) = &self.uid {
            let context = context.with_struct("Commit", "uid");

            results.push(uid.validate_with_context(context));
        }

        if let Some(url) = &self.url {
            let context = context.with_struct("Commit", "url");

            results.push(url.validate_with_context(context));
        }

        if let Some(author) = &self.author {
            let context = context.with_struct("Commit", "author");

            results.push(author.validate_with_context(context));
        }

        if let Some(committer) = &self.committer {
            let context = context.with_struct("Commit", "committer");

            results.push(committer.validate_with_context(context));
        }

        if let Some(message) = &self.message {
            let context = context.with_struct("Commit", "message");

            results.push(message.validate_with_context(context));
        }

        results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commits(pub Vec<Commit>);

impl Validate for Commits {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut results: Vec<ValidationResult> = vec![];

        for (index, commit) in self.0.iter().enumerate() {
            let commit_context =
                context.extend_context(vec![ValidationPathComponent::Array { index }]);
            results.push(commit.validate_with_context(commit_context));
        }

        results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diff {
    pub text: Option<AttachedText>,
    pub url: Option<Uri>,
}

impl Validate for Diff {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut results: Vec<ValidationResult> = vec![];

        if let Some(text) = &self.text {
            let context = context.with_struct("Diff", "text");

            results.push(text.validate_with_context(context));
        }

        if let Some(url) = &self.url {
            let context = context.with_struct("Diff", "url");

            results.push(url.validate_with_context(context));
        }

        results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentifiableAction {
    pub timestamp: Option<DateTime>,
    pub name: Option<NormalizedString>,
    pub email: Option<NormalizedString>,
}

impl Validate for IdentifiableAction {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut results: Vec<ValidationResult> = vec![];

        if let Some(timestamp) = &self.timestamp {
            let context = context.with_struct("IdentifiableAction", "timestamp");

            results.push(timestamp.validate_with_context(context));
        }

        if let Some(name) = &self.name {
            let context = context.with_struct("IdentifiableAction", "name");

            results.push(name.validate_with_context(context));
        }

        if let Some(email) = &self.email {
            let context = context.with_struct("IdentifiableAction", "email");

            results.push(email.validate_with_context(context));
        }

        results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    pub issue_type: IssueClassification,
    pub id: Option<NormalizedString>,
    pub name: Option<NormalizedString>,
    pub description: Option<NormalizedString>,
    pub source: Option<Source>,
    pub references: Option<Vec<Uri>>,
}

impl Validate for Issue {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut results: Vec<ValidationResult> = vec![];

        let issue_context = context.with_struct("Issue", "issue_type");

        results.push(self.issue_type.validate_with_context(issue_context));

        if let Some(id) = &self.id {
            let context = context.with_struct("Issue", "id");

            results.push(id.validate_with_context(context));
        }

        if let Some(name) = &self.name {
            let context = context.with_struct("Issue", "name");

            results.push(name.validate_with_context(context));
        }

        if let Some(description) = &self.description {
            let context = context.with_struct("Issue", "description");

            results.push(description.validate_with_context(context));
        }

        if let Some(source) = &self.source {
            let context = context.with_struct("Issue", "source");

            results.push(source.validate_with_context(context));
        }

        if let Some(reference) = &self.references {
            for (index, reference) in reference.iter().enumerate() {
                let context = context.extend_context(vec![
                    ValidationPathComponent::Struct {
                        struct_name: "Issue".to_string(),
                        field_name: "references".to_string(),
                    },
                    ValidationPathComponent::Array { index },
                ]);
                results.push(reference.validate_with_context(context));
            }
        }

        results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueClassification {
    Defect,
    Enhancement,
    Security,
    #[doc(hidden)]
    UnknownIssueClassification(String),
}

impl ToString for IssueClassification {
    fn to_string(&self) -> String {
        match self {
            IssueClassification::Defect => "defect",
            IssueClassification::Enhancement => "enhancement",
            IssueClassification::Security => "security",
            IssueClassification::UnknownIssueClassification(uic) => uic,
        }
        .to_string()
    }
}

impl IssueClassification {
    pub(crate) fn new_unchecked<A: AsRef<str>>(value: A) -> Self {
        match value.as_ref() {
            "defect" => Self::Defect,
            "enhancement" => Self::Enhancement,
            "security" => Self::Security,
            unknown => Self::UnknownIssueClassification(unknown.to_string()),
        }
    }
}

impl Validate for IssueClassification {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        match self {
            IssueClassification::UnknownIssueClassification(_) => {
                ValidationResult::failure("Unknown issue classification", context)
            }
            _ => ValidationResult::Passed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    pub patch_type: PatchClassification,
    pub diff: Option<Diff>,
    pub resolves: Option<Vec<Issue>>,
}

impl Validate for Patch {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut results: Vec<ValidationResult> = vec![];

        let patch_type_context = context.with_struct("Patch", "patch_type");

        results.push(self.patch_type.validate_with_context(patch_type_context));

        if let Some(diff) = &self.diff {
            let context = context.with_struct("Patch", "diff");

            results.push(diff.validate_with_context(context));
        }

        if let Some(resolves) = &self.resolves {
            for (index, resolve) in resolves.iter().enumerate() {
                let context = context.extend_context(vec![
                    ValidationPathComponent::Struct {
                        struct_name: "Patch".to_string(),
                        field_name: "resolves".to_string(),
                    },
                    ValidationPathComponent::Array { index },
                ]);
                results.push(resolve.validate_with_context(context));
            }
        }

        results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patches(pub Vec<Patch>);

impl Validate for Patches {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut results: Vec<ValidationResult> = vec![];

        for (index, patch) in self.0.iter().enumerate() {
            let context = context.extend_context(vec![ValidationPathComponent::Array { index }]);
            results.push(patch.validate_with_context(context));
        }

        results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatchClassification {
    Unofficial,
    Monkey,
    Backport,
    CherryPick,
    #[doc(hidden)]
    UnknownPatchClassification(String),
}

impl ToString for PatchClassification {
    fn to_string(&self) -> String {
        match self {
            PatchClassification::Unofficial => "unofficial",
            PatchClassification::Monkey => "monkey",
            PatchClassification::Backport => "backport",
            PatchClassification::CherryPick => "cherry-pick",
            PatchClassification::UnknownPatchClassification(upc) => upc,
        }
        .to_string()
    }
}

impl PatchClassification {
    pub(crate) fn new_unchecked<A: AsRef<str>>(value: A) -> Self {
        match value.as_ref() {
            "unofficial" => Self::Unofficial,
            "monkey" => Self::Monkey,
            "backport" => Self::Backport,
            "cherry-pick" => Self::CherryPick,
            unknown => Self::UnknownPatchClassification(unknown.to_string()),
        }
    }
}

impl Validate for PatchClassification {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        match self {
            PatchClassification::UnknownPatchClassification(_) => {
                ValidationResult::failure("Unknown patch classification", context)
            }
            _ => ValidationResult::Passed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub name: Option<NormalizedString>,
    pub url: Option<Uri>,
}

impl Validate for Source {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut results: Vec<ValidationResult> = vec![];

        if let Some(name) = &self.name {
            let context = context.with_struct("Source", "name");

            results.push(name.validate_with_context(context));
        }

        if let Some(url) = &self.url {
            let context = context.with_struct("Source", "url");

            results.push(url.validate_with_context(context));
        }

        results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result))
    }
}

#[cfg(test)]
mod test {
    use crate::validation::FailureReason;

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn valid_commits_should_pass_validation() {
        let validation_result = Commits(vec![Commit {
            uid: Some(NormalizedString("no_whitespace".to_string())),
            url: Some(Uri("https://www.example.com".to_string())),
            author: Some(IdentifiableAction {
                timestamp: Some(DateTime("1969-06-28T01:20:00.00-04:00".to_string())),
                name: Some(NormalizedString("Name".to_string())),
                email: Some(NormalizedString("email@example.com".to_string())),
            }),
            committer: Some(IdentifiableAction {
                timestamp: Some(DateTime("1969-06-28T01:20:00.00-04:00".to_string())),
                name: Some(NormalizedString("Name".to_string())),
                email: Some(NormalizedString("email@example.com".to_string())),
            }),
            message: Some(NormalizedString("no_whitespace".to_string())),
        }])
        .validate();

        assert_eq!(validation_result, ValidationResult::Passed);
    }

    #[test]
    fn invalid_commits_should_fail_validation() {
        let validation_result = Commits(vec![Commit {
            uid: Some(NormalizedString("spaces and\ttabs".to_string())),
            url: Some(Uri("invalid uri".to_string())),
            author: Some(IdentifiableAction {
                timestamp: Some(DateTime("Thursday".to_string())),
                name: Some(NormalizedString("spaces and\ttabs".to_string())),
                email: Some(NormalizedString("spaces and\ttabs".to_string())),
            }),
            committer: Some(IdentifiableAction {
                timestamp: Some(DateTime("1970-01-01".to_string())),
                name: Some(NormalizedString("spaces and\ttabs".to_string())),
                email: Some(NormalizedString("spaces and\ttabs".to_string())),
            }),
            message: Some(NormalizedString("spaces and\ttabs".to_string())),
        }])
        .validate();

        assert_eq!(
            validation_result,
            ValidationResult::Failed {
                reasons: vec![
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Commit", "uid")
                    ),
                    FailureReason::new(
                        "Uri does not conform to RFC 3986",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Commit", "url")
                    ),
                    FailureReason::new(
                        "DateTime does not conform to ISO 8601",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Commit", "author")
                            .with_struct("IdentifiableAction", "timestamp")
                    ),
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Commit", "author")
                            .with_struct("IdentifiableAction", "name")
                    ),
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Commit", "author")
                            .with_struct("IdentifiableAction", "email")
                    ),
                    FailureReason::new(
                        "DateTime does not conform to ISO 8601",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Commit", "committer")
                            .with_struct("IdentifiableAction", "timestamp")
                    ),
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Commit", "committer")
                            .with_struct("IdentifiableAction", "name")
                    ),
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Commit", "committer")
                            .with_struct("IdentifiableAction", "email")
                    ),
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Commit", "message")
                    ),
                ]
            }
        );
    }

    #[test]
    fn valid_patches_should_pass_validation() {
        let validation_result = Patches(vec![Patch {
            patch_type: PatchClassification::Backport,
            diff: Some(Diff {
                text: Some(AttachedText {
                    content_type: None,
                    encoding: None,
                    content: "content".to_string(),
                }),
                url: Some(Uri("https://www.example.com".to_string())),
            }),
            resolves: Some(vec![Issue {
                issue_type: IssueClassification::Defect,
                id: Some(NormalizedString("issue_id".to_string())),
                name: Some(NormalizedString("issue_name".to_string())),
                description: Some(NormalizedString("issue_description".to_string())),
                source: Some(Source {
                    name: Some(NormalizedString("source_name".to_string())),
                    url: Some(Uri("https://example.com".to_string())),
                }),
                references: Some(vec![Uri("https://example.com".to_string())]),
            }]),
        }])
        .validate();

        assert_eq!(validation_result, ValidationResult::Passed);
    }

    #[test]
    fn invalid_patches_should_fail_validation() {
        let validation_result = Patches(vec![Patch {
            patch_type: PatchClassification::UnknownPatchClassification("unknown".to_string()),
            diff: Some(Diff {
                text: Some(AttachedText {
                    content_type: Some(NormalizedString("spaces and \ttabs".to_string())),
                    encoding: None,
                    content: "content".to_string(),
                }),
                url: Some(Uri("invalid uri".to_string())),
            }),
            resolves: Some(vec![Issue {
                issue_type: IssueClassification::UnknownIssueClassification("unknown".to_string()),
                id: Some(NormalizedString("spaces and \ttabs".to_string())),
                name: Some(NormalizedString("spaces and \ttabs".to_string())),
                description: Some(NormalizedString("spaces and \ttabs".to_string())),
                source: Some(Source {
                    name: Some(NormalizedString("spaces and \ttabs".to_string())),
                    url: Some(Uri("invalid uri".to_string())),
                }),
                references: Some(vec![Uri("invalid uri".to_string())]),
            }]),
        }])
        .validate();

        assert_eq!(
            validation_result,
            ValidationResult::Failed {
                reasons: vec![
                    FailureReason::new(
                        "Unknown patch classification",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Patch", "patch_type")
                    ),
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Patch", "diff")
                            .with_struct("Diff", "text")
                            .with_struct("AttachedText", "content_type")
                    ),
                    FailureReason::new(
                        "Uri does not conform to RFC 3986",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Patch", "diff")
                            .with_struct("Diff", "url")
                    ),
                    FailureReason::new(
                        "Unknown issue classification",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Patch", "resolves")
                            .with_index(0)
                            .with_struct("Issue", "issue_type")
                    ),
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Patch", "resolves")
                            .with_index(0)
                            .with_struct("Issue", "id")
                    ),
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Patch", "resolves")
                            .with_index(0)
                            .with_struct("Issue", "name")
                    ),
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Patch", "resolves")
                            .with_index(0)
                            .with_struct("Issue", "description")
                    ),
                    FailureReason::new(
                        "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Patch", "resolves")
                            .with_index(0)
                            .with_struct("Issue", "source")
                            .with_struct("Source", "name")
                    ),
                    FailureReason::new(
                        "Uri does not conform to RFC 3986",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Patch", "resolves")
                            .with_index(0)
                            .with_struct("Issue", "source")
                            .with_struct("Source", "url")
                    ),
                    FailureReason::new(
                        "Uri does not conform to RFC 3986",
                        ValidationContext::new()
                            .with_index(0)
                            .with_struct("Patch", "resolves")
                            .with_index(0)
                            .with_struct("Issue", "references")
                            .with_index(0)
                    ),
                ]
            }
        );
    }
}
