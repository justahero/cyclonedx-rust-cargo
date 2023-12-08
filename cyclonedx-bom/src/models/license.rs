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

use std::convert::TryFrom;

use crate::external_models::spdx::SpdxIdentifierError;
use crate::external_models::{
    normalized_string::NormalizedString,
    spdx::{SpdxExpression, SpdxIdentifier},
    uri::Uri,
};
use crate::models::attached_text::AttachedText;
use crate::validation::{Validate, ValidationContext, ValidationPathComponent, ValidationResult};

/// Represents whether a license is a named license or an SPDX license expression
///
/// As defined via the [CycloneDX XML schema](https://cyclonedx.org/docs/1.3/xml/#type_licenseChoiceType)
#[derive(Debug, PartialEq, Eq)]
pub enum LicenseChoice {
    License(License),
    Expression(SpdxExpression),
}

impl LicenseChoice {
    pub fn is_license(&self) -> bool {
        matches!(self, Self::License(_))
    }
}

impl Validate for LicenseChoice {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut result = ValidationResult::default();

        match self {
            LicenseChoice::License(license) => {
                let license_context =
                    context.extend_context(vec![ValidationPathComponent::EnumVariant {
                        variant_name: "License".to_string(),
                    }]);
                result.merge(license.validate_with_context(license_context));
            }
            LicenseChoice::Expression(expression) => {
                let expression_context =
                    context.extend_context(vec![ValidationPathComponent::EnumVariant {
                        variant_name: "Expression".to_string(),
                    }]);
                result.merge(expression.validate_with_context(expression_context));
            }
        }
        result
    }
}

/// Represents a license with identifier, text, and url
///
/// Defined via the [CycloneDX XML schema](https://cyclonedx.org/docs/1.3/xml/#type_licenseType)
#[derive(Debug, PartialEq, Eq)]
pub struct License {
    pub license_identifier: LicenseIdentifier,
    pub text: Option<AttachedText>,
    pub url: Option<Uri>,
}

impl License {
    /// Constructs a `License` with a named license identifier
    /// ```
    /// use cyclonedx_bom::models::license::License;
    ///
    /// let license = License::named_license("Example License 1.0");
    /// ```
    pub fn named_license(license: &str) -> Self {
        Self {
            license_identifier: LicenseIdentifier::Name(NormalizedString::new(license)),
            text: None,
            url: None,
        }
    }

    /// Constructs a `License` with an SPDX license identifier
    /// ```
    /// use cyclonedx_bom::models::license::License;
    ///
    /// let license = License::license_id("LGPL-3.0-or-later");
    /// ```
    pub fn license_id(license: &str) -> Result<Self, SpdxIdentifierError> {
        Ok(Self {
            license_identifier: LicenseIdentifier::SpdxId(SpdxIdentifier::try_from(
                license.to_owned(),
            )?),
            text: None,
            url: None,
        })
    }
}

impl Validate for License {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut result = ValidationResult::default();

        let license_identifier_context =
            context.extend_context_with_struct_field("License", "license_identifier");

        result.merge(
            self.license_identifier
                .validate_with_context(license_identifier_context),
        );

        if let Some(text) = &self.text {
            let context = context.extend_context_with_struct_field("License", "text");

            result.merge(text.validate_with_context(context));
        }

        if let Some(url) = &self.url {
            let context = context.extend_context_with_struct_field("License", "url");

            result.merge(url.validate_with_context(context));
        }

        result
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Licenses(pub Vec<LicenseChoice>);

impl Validate for Licenses {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut result = ValidationResult::default();

        for (index, license_choice) in self.0.iter().enumerate() {
            let license_choice_context =
                context.extend_context(vec![ValidationPathComponent::Array { index }]);
            result.merge(license_choice.validate_with_context(license_choice_context));
        }

        result
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LicenseIdentifier {
    /// An SPDX license identifier from the list on the [SPDX website](https://spdx.org/licenses/).
    SpdxId(SpdxIdentifier),
    /// A license that is not in the SPDX license list (eg. a proprietary license or a license not yet recognized by SPDX).
    Name(NormalizedString),
}

impl Validate for LicenseIdentifier {
    fn validate_with_context(&self, context: ValidationContext) -> ValidationResult {
        let mut result = ValidationResult::default();
        match self {
            LicenseIdentifier::Name(name) => {
                let name_context =
                    context.extend_context(vec![ValidationPathComponent::EnumVariant {
                        variant_name: "Name".to_string(),
                    }]);
                result.merge(name.validate_with_context(name_context));
            }
            LicenseIdentifier::SpdxId(id) => {
                let spdxid_context =
                    context.extend_context(vec![ValidationPathComponent::EnumVariant {
                        variant_name: "SpdxId".to_string(),
                    }]);
                result.merge(id.validate_with_context(spdxid_context));
            }
        }
        result
    }
}

#[cfg(test)]
mod test {
    use crate::validation::FailureReason;

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn it_should_pass_validation() {
        let validation_result = Licenses(vec![LicenseChoice::Expression(SpdxExpression(
            "MIT OR Apache-2.0".to_string(),
        ))])
        .validate_with_context(ValidationContext::default());

        assert!(validation_result.passed());
    }

    #[test]
    fn it_should_fail_validation_for_license_name() {
        let validation_result = Licenses(vec![LicenseChoice::License(License {
            license_identifier: LicenseIdentifier::Name(NormalizedString(
                "spaces and \ttabs".to_string(),
            )),
            text: None,
            url: None,
        })])
        .validate_with_context(ValidationContext::default());

        assert_eq!(
            validation_result.reasons(),
            [FailureReason {
                message: "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                    .to_string(),
                context: ValidationContext(vec![
                    ValidationPathComponent::Array { index: 0 },
                    ValidationPathComponent::EnumVariant {
                        variant_name: "License".to_string()
                    },
                    ValidationPathComponent::Struct {
                        struct_name: "License".to_string(),
                        field_name: "license_identifier".to_string(),
                    },
                    ValidationPathComponent::EnumVariant {
                        variant_name: "Name".to_string()
                    },
                ])
            }]
        );
    }

    #[test]
    fn it_should_fail_validation_for_license_id() {
        let validation_result = Licenses(vec![LicenseChoice::License(License {
            license_identifier: LicenseIdentifier::SpdxId(SpdxIdentifier("Apache=2.0".to_string())),
            text: None,
            url: None,
        })])
        .validate_with_context(ValidationContext::default());

        assert_eq!(
            validation_result.reasons(),
            [FailureReason {
                message: "SPDX identifier is not valid".to_string(),
                context: ValidationContext(vec![
                    ValidationPathComponent::Array { index: 0 },
                    ValidationPathComponent::EnumVariant {
                        variant_name: "License".to_string()
                    },
                    ValidationPathComponent::Struct {
                        struct_name: "License".to_string(),
                        field_name: "license_identifier".to_string(),
                    },
                    ValidationPathComponent::EnumVariant {
                        variant_name: "SpdxId".to_string()
                    },
                ])
            }]
        );
    }

    #[test]
    fn it_should_fail_validation_for_license_expression() {
        let validation_result = Licenses(vec![LicenseChoice::Expression(SpdxExpression(
            "MIT OR".to_string(),
        ))])
        .validate_with_context(ValidationContext::default());

        assert_eq!(
            validation_result.reasons(),
            [FailureReason {
                message: "SPDX expression is not valid".to_string(),
                context: ValidationContext(vec![
                    ValidationPathComponent::Array { index: 0 },
                    ValidationPathComponent::EnumVariant {
                        variant_name: "Expression".to_string()
                    }
                ])
            }]
        );
    }

    #[test]
    fn it_should_merge_validations_correctly_license_choice_licenses() {
        let validation_result = Licenses(vec![
            LicenseChoice::License(License {
                license_identifier: LicenseIdentifier::Name(NormalizedString("MIT".to_string())),
                text: None,
                url: None,
            }),
            LicenseChoice::License(License {
                license_identifier: LicenseIdentifier::Name(NormalizedString(
                    "spaces and \ttabs".to_string(),
                )),
                text: None,
                url: None,
            }),
            LicenseChoice::License(License {
                license_identifier: LicenseIdentifier::SpdxId(SpdxIdentifier(
                    "Apache=2.0".to_string(),
                )),
                text: None,
                url: None,
            }),
        ])
        .validate_with_context(ValidationContext::default());

        assert_eq!(
            validation_result.reasons(),
            [
                FailureReason {
                    message: "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                        .to_string(),
                    context: ValidationContext(vec![
                        ValidationPathComponent::Array { index: 1 },
                        ValidationPathComponent::EnumVariant {
                            variant_name: "License".to_string()
                        },
                        ValidationPathComponent::Struct {
                            struct_name: "License".to_string(),
                            field_name: "license_identifier".to_string(),
                        },
                        ValidationPathComponent::EnumVariant {
                            variant_name: "Name".to_string()
                        },
                    ])
                },
                FailureReason {
                    message: "SPDX identifier is not valid".to_string(),
                    context: ValidationContext(vec![
                        ValidationPathComponent::Array { index: 2 },
                        ValidationPathComponent::EnumVariant {
                            variant_name: "License".to_string()
                        },
                        ValidationPathComponent::Struct {
                            struct_name: "License".to_string(),
                            field_name: "license_identifier".to_string(),
                        },
                        ValidationPathComponent::EnumVariant {
                            variant_name: "SpdxId".to_string()
                        },
                    ])
                }
            ]
        );
    }

    #[test]
    fn it_should_merge_validations_correctly_license_choice_expressions() {
        let validation_result = Licenses(vec![
            LicenseChoice::Expression(SpdxExpression("MIT OR Apache-2.0".to_string())),
            LicenseChoice::Expression(SpdxExpression("MIT OR".to_string())),
            LicenseChoice::Expression(SpdxExpression("MIT OR".to_string())),
        ])
        .validate_with_context(ValidationContext::default());

        assert_eq!(
            validation_result.reasons(),
            [
                FailureReason {
                    message: "SPDX expression is not valid".to_string(),
                    context: ValidationContext(vec![
                        ValidationPathComponent::Array { index: 1 },
                        ValidationPathComponent::EnumVariant {
                            variant_name: "Expression".to_string()
                        }
                    ])
                },
                FailureReason {
                    message: "SPDX expression is not valid".to_string(),
                    context: ValidationContext(vec![
                        ValidationPathComponent::Array { index: 2 },
                        ValidationPathComponent::EnumVariant {
                            variant_name: "Expression".to_string()
                        }
                    ])
                }
            ]
        );
    }
}
