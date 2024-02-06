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
use serde::Serialize;
use validator::Validate;

use crate::{
    external_models::{
        date_time::{validate_date_time, DateTime},
        normalized_string::{validate_normalized_string, NormalizedString},
        uri::{validate_uri, Uri},
    },
    validation::{
        FailureReason, ValidateOld, ValidationContext, ValidationError, ValidationPathComponent,
        ValidationResult,
    },
};

use super::{attached_text::AttachedText, create_validation_errors};

#[derive(Clone, Debug, PartialEq, Eq, validator::Validate)]
pub struct Commit {
    #[validate(custom(function = "validate_normalized_string"))]
    pub uid: Option<NormalizedString>,
    #[validate(custom(function = "validate_uri"))]
    pub url: Option<Uri>,
    #[validate]
    pub author: Option<IdentifiableAction>,
    #[validate]
    pub committer: Option<IdentifiableAction>,
    #[validate(custom(function = "validate_normalized_string"))]
    pub message: Option<NormalizedString>,
}

impl ValidateOld for Commit {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let mut results: Vec<ValidationResult> = vec![];

        if let Some(uid) = &self.uid {
            let context = context.extend_context_with_struct_field("Commit", "uid");

            results.push(uid.validate_with_context(context)?);
        }

        if let Some(url) = &self.url {
            let context = context.extend_context_with_struct_field("Commit", "url");

            results.push(url.validate_with_context(context)?);
        }

        if let Some(author) = &self.author {
            let context = context.extend_context_with_struct_field("Commit", "author");

            results.push(author.validate_with_context(context)?);
        }

        if let Some(committer) = &self.committer {
            let context = context.extend_context_with_struct_field("Commit", "committer");

            results.push(committer.validate_with_context(context)?);
        }

        if let Some(message) = &self.message {
            let context = context.extend_context_with_struct_field("Commit", "message");

            results.push(message.validate_with_context(context)?);
        }

        Ok(results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commits(pub Vec<Commit>);

impl validator::Validate for Commits {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut result = std::result::Result::Ok(());

        for commit in &self.0 {
            result = validator::ValidationErrors::merge(result, "", commit.validate());
        }

        result
    }
}

impl ValidateOld for Commits {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let mut results: Vec<ValidationResult> = vec![];

        for (index, commit) in self.0.iter().enumerate() {
            let commit_context =
                context.extend_context(vec![ValidationPathComponent::Array { index }]);
            results.push(commit.validate_with_context(commit_context)?);
        }

        Ok(results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, validator::Validate)]
pub struct Diff {
    #[validate]
    pub text: Option<AttachedText>,
    #[validate(custom(function = "validate_uri"))]
    pub url: Option<Uri>,
}

impl ValidateOld for Diff {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let mut results: Vec<ValidationResult> = vec![];

        if let Some(text) = &self.text {
            let context = context.extend_context_with_struct_field("Diff", "text");

            results.push(text.validate_with_context(context)?);
        }

        if let Some(url) = &self.url {
            let context = context.extend_context_with_struct_field("Diff", "url");

            results.push(url.validate_with_context(context)?);
        }

        Ok(results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, validator::Validate)]
pub struct IdentifiableAction {
    #[validate(custom(function = "validate_date_time"))]
    pub timestamp: Option<DateTime>,
    #[validate(custom(function = "validate_normalized_string"))]
    pub name: Option<NormalizedString>,
    #[validate(custom(function = "validate_normalized_string"))]
    pub email: Option<NormalizedString>,
}

impl ValidateOld for IdentifiableAction {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let mut results: Vec<ValidationResult> = vec![];

        if let Some(timestamp) = &self.timestamp {
            let context =
                context.extend_context_with_struct_field("IdentifiableAction", "timestamp");

            results.push(timestamp.validate_with_context(context)?);
        }

        if let Some(name) = &self.name {
            let context = context.extend_context_with_struct_field("IdentifiableAction", "name");

            results.push(name.validate_with_context(context)?);
        }

        if let Some(email) = &self.email {
            let context = context.extend_context_with_struct_field("IdentifiableAction", "email");

            results.push(email.validate_with_context(context)?);
        }

        Ok(results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, validator::Validate)]
pub struct Issue {
    #[validate]
    pub issue_type: IssueClassification,
    #[validate(custom(function = "validate_normalized_string"))]
    pub id: Option<NormalizedString>,
    #[validate(custom(function = "validate_normalized_string"))]
    pub name: Option<NormalizedString>,
    #[validate(custom(function = "validate_normalized_string"))]
    pub description: Option<NormalizedString>,
    #[validate]
    pub source: Option<Source>,
    #[validate]
    pub references: Option<Vec<Uri>>,
}

impl ValidateOld for Issue {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let mut results: Vec<ValidationResult> = vec![];

        let issue_context = context.extend_context_with_struct_field("Issue", "issue_type");

        results.push(self.issue_type.validate_with_context(issue_context)?);

        if let Some(id) = &self.id {
            let context = context.extend_context_with_struct_field("Issue", "id");

            results.push(id.validate_with_context(context)?);
        }

        if let Some(name) = &self.name {
            let context = context.extend_context_with_struct_field("Issue", "name");

            results.push(name.validate_with_context(context)?);
        }

        if let Some(description) = &self.description {
            let context = context.extend_context_with_struct_field("Issue", "description");

            results.push(description.validate_with_context(context)?);
        }

        if let Some(source) = &self.source {
            let context = context.extend_context_with_struct_field("Issue", "source");

            results.push(source.validate_with_context(context)?);
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
                results.push(reference.validate_with_context(context)?);
            }
        }

        Ok(results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result)))
    }
}

pub fn validate_issue_classification(
    classification: &IssueClassification,
) -> Result<(), validator::ValidationError> {
    if matches!(
        classification,
        IssueClassification::UnknownIssueClassification(_)
    ) {
        return Err(validator::ValidationError::new(
            "Unknown issue classification",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IssueClassification {
    Defect,
    Enhancement,
    Security,
    #[doc(hidden)]
    UnknownIssueClassification(String),
}

impl validator::Validate for IssueClassification {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        validate_issue_classification(self).map_err(create_validation_errors)
    }
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

impl ValidateOld for IssueClassification {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        match self {
            IssueClassification::UnknownIssueClassification(_) => Ok(ValidationResult::Failed {
                reasons: vec![FailureReason {
                    message: "Unknown issue classification".to_string(),
                    context,
                }],
            }),
            _ => Ok(ValidationResult::Passed),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, validator::Validate)]
pub struct Patch {
    #[validate(custom(function = "validate_patch_classification"))]
    pub patch_type: PatchClassification,
    #[validate]
    pub diff: Option<Diff>,
    #[validate]
    pub resolves: Option<Vec<Issue>>,
}

impl ValidateOld for Patch {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let mut results: Vec<ValidationResult> = vec![];

        let patch_type_context = context.extend_context_with_struct_field("Patch", "patch_type");

        results.push(self.patch_type.validate_with_context(patch_type_context)?);

        if let Some(diff) = &self.diff {
            let context = context.extend_context_with_struct_field("Patch", "diff");

            results.push(diff.validate_with_context(context)?);
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
                results.push(resolve.validate_with_context(context)?);
            }
        }

        Ok(results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result)))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patches(pub Vec<Patch>);

impl validator::Validate for Patches {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut result = std::result::Result::Ok(());

        for patch in &self.0 {
            result = validator::ValidationErrors::merge(result, "", patch.validate());
        }

        result
    }
}

impl ValidateOld for Patches {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let mut results: Vec<ValidationResult> = vec![];

        for (index, patch) in self.0.iter().enumerate() {
            let context = context.extend_context(vec![ValidationPathComponent::Array { index }]);
            results.push(patch.validate_with_context(context)?);
        }

        Ok(results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result)))
    }
}

pub fn validate_patch_classification(
    classification: &PatchClassification,
) -> Result<(), validator::ValidationError> {
    if matches!(
        classification,
        PatchClassification::UnknownPatchClassification(_)
    ) {
        return Err(validator::ValidationError::new(
            "Unknown patch classification",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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

impl ValidateOld for PatchClassification {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        match self {
            PatchClassification::UnknownPatchClassification(_) => Ok(ValidationResult::Failed {
                reasons: vec![FailureReason {
                    message: "Unknown patch classification".to_string(),
                    context,
                }],
            }),
            _ => Ok(ValidationResult::Passed),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, validator::Validate)]
pub struct Source {
    #[validate(custom(function = "validate_normalized_string"))]
    pub name: Option<NormalizedString>,
    #[validate(custom(function = "validate_uri"))]
    pub url: Option<Uri>,
}

impl ValidateOld for Source {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        let mut results: Vec<ValidationResult> = vec![];

        if let Some(name) = &self.name {
            let context = context.extend_context_with_struct_field("Source", "name");

            results.push(name.validate_with_context(context)?);
        }

        if let Some(url) = &self.url {
            let context = context.extend_context_with_struct_field("Source", "url");

            results.push(url.validate_with_context(context)?);
        }

        Ok(results
            .into_iter()
            .fold(ValidationResult::default(), |acc, result| acc.merge(result)))
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
        .validate_with_context(ValidationContext::default())
        .expect("Error while validating");

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
        .validate_with_context(ValidationContext::default())
        .expect("Error while validating");

        assert_eq!(
            validation_result,
            ValidationResult::Failed {
                reasons: vec![
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Commit".to_string(),
                                field_name: "uid".to_string()
                            }
                        ])
                    },
                    FailureReason {
                        message: "Uri does not conform to RFC 3986".to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Commit".to_string(),
                                field_name: "url".to_string()
                            }
                        ])
                    },
                    FailureReason {
                        message: "DateTime does not conform to ISO 8601".to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Commit".to_string(),
                                field_name: "author".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "IdentifiableAction".to_string(),
                                field_name: "timestamp".to_string()
                            }
                        ])
                    },
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Commit".to_string(),
                                field_name: "author".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "IdentifiableAction".to_string(),
                                field_name: "name".to_string()
                            }
                        ])
                    },
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Commit".to_string(),
                                field_name: "author".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "IdentifiableAction".to_string(),
                                field_name: "email".to_string()
                            }
                        ])
                    },
                    FailureReason {
                        message: "DateTime does not conform to ISO 8601".to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Commit".to_string(),
                                field_name: "committer".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "IdentifiableAction".to_string(),
                                field_name: "timestamp".to_string()
                            }
                        ])
                    },
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Commit".to_string(),
                                field_name: "committer".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "IdentifiableAction".to_string(),
                                field_name: "name".to_string()
                            }
                        ])
                    },
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Commit".to_string(),
                                field_name: "committer".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "IdentifiableAction".to_string(),
                                field_name: "email".to_string()
                            }
                        ])
                    },
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Commit".to_string(),
                                field_name: "message".to_string()
                            },
                        ])
                    },
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
        .validate_with_context(ValidationContext::default())
        .expect("Error while validating");

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
        .validate_with_context(ValidationContext::default())
        .expect("Error while validating");

        assert_eq!(
            validation_result,
            ValidationResult::Failed {
                reasons: vec![
                    FailureReason {
                        message: "Unknown patch classification".to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Patch".to_string(),
                                field_name: "patch_type".to_string()
                            },
                        ])
                    },
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Patch".to_string(),
                                field_name: "diff".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "Diff".to_string(),
                                field_name: "text".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "AttachedText".to_string(),
                                field_name: "content_type".to_string()
                            }
                        ])
                    },
                    FailureReason {
                        message: "Uri does not conform to RFC 3986".to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Patch".to_string(),
                                field_name: "diff".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "Diff".to_string(),
                                field_name: "url".to_string()
                            },
                        ])
                    },
                    FailureReason {
                        message: "Unknown issue classification".to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Patch".to_string(),
                                field_name: "resolves".to_string()
                            },
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Issue".to_string(),
                                field_name: "issue_type".to_string()
                            },
                        ])
                    },
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Patch".to_string(),
                                field_name: "resolves".to_string()
                            },
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Issue".to_string(),
                                field_name: "id".to_string()
                            },
                        ])
                    },
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Patch".to_string(),
                                field_name: "resolves".to_string()
                            },
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Issue".to_string(),
                                field_name: "name".to_string()
                            },
                        ])
                    },
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Patch".to_string(),
                                field_name: "resolves".to_string()
                            },
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Issue".to_string(),
                                field_name: "description".to_string()
                            },
                        ])
                    },
                    FailureReason {
                        message:
                            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                                .to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Patch".to_string(),
                                field_name: "resolves".to_string()
                            },
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Issue".to_string(),
                                field_name: "source".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "Source".to_string(),
                                field_name: "name".to_string()
                            },
                        ])
                    },
                    FailureReason {
                        message: "Uri does not conform to RFC 3986".to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Patch".to_string(),
                                field_name: "resolves".to_string()
                            },
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Issue".to_string(),
                                field_name: "source".to_string()
                            },
                            ValidationPathComponent::Struct {
                                struct_name: "Source".to_string(),
                                field_name: "url".to_string()
                            },
                        ])
                    },
                    FailureReason {
                        message: "Uri does not conform to RFC 3986".to_string(),
                        context: ValidationContext(vec![
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Patch".to_string(),
                                field_name: "resolves".to_string()
                            },
                            ValidationPathComponent::Array { index: 0 },
                            ValidationPathComponent::Struct {
                                struct_name: "Issue".to_string(),
                                field_name: "references".to_string()
                            },
                            ValidationPathComponent::Array { index: 0 }
                        ])
                    },
                ]
            }
        );
    }
}
