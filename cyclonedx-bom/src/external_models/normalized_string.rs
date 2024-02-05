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

use crate::validation::{
    FailureReason, ValidateOld, ValidationContext, ValidationError, ValidationResult,
};
use std::fmt::Display;
use std::ops::Deref;

/// A string that does not contain carriage return, line feed, or tab characters
///
/// Defined via the [XML schema](https://www.w3.org/TR/xmlschema-2/#normalizedString)
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct NormalizedString(pub(crate) String);

/// Validates given string.
pub fn validate_normalized_string(input: &str) -> Result<(), validator::ValidationError> {
    if input.contains("\r\n")
        || input.contains('\r')
        || input.contains('\n')
        || input.contains('\t')
    {
        return Err(validator::ValidationError::new(
            "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n",
        ));
    }
    Ok(())
}

impl validator::Validate for NormalizedString {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        validate_normalized_string(self).map_err(|err| {
            let mut errors = validator::ValidationErrors::new();
            errors.add("", err);
            errors
        })
    }
}

impl NormalizedString {
    /// Construct a `NormalizedString` by replacing all of the invalid characters with spaces
    /// ```
    /// use cyclonedx_bom::prelude::*;
    ///
    /// let normalized_string = NormalizedString::new("A\r\nstring\rwith\ninvalid\tcharacters");
    /// assert_eq!(normalized_string.to_string(), "A string with invalid characters".to_string());
    /// ```
    pub fn new(value: &str) -> Self {
        let value = value.replace("\r\n", " ").replace(['\r', '\n', '\t'], " ");
        NormalizedString(value)
    }

    /// Allow for the existence of invalid inputs from other data sources
    pub(crate) fn new_unchecked(value: String) -> Self {
        NormalizedString(value)
    }
}

impl Deref for NormalizedString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for NormalizedString {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for NormalizedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ValidateOld for NormalizedString {
    fn validate_with_context(
        &self,
        context: ValidationContext,
    ) -> Result<ValidationResult, ValidationError> {
        if self.0.contains("\r\n")
            || self.0.contains('\r')
            || self.0.contains('\n')
            || self.0.contains('\t')
        {
            return Ok(ValidationResult::Failed {
                reasons: vec![FailureReason {
                    message: "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                        .to_string(),
                    context,
                }],
            });
        }

        Ok(ValidationResult::Passed)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::validation::FailureReason;
    use pretty_assertions::assert_eq;

    #[test]
    fn it_should_normalize_strings() {
        assert_eq!(
            NormalizedString("no_whitespace".to_string()),
            NormalizedString::new("no_whitespace")
        );
        assert_eq!(
            NormalizedString("spaces and tabs".to_string()),
            NormalizedString::new("spaces and\ttabs")
        );
        assert_eq!(
            NormalizedString("carriage returns and linefeeds".to_string()),
            NormalizedString::new("carriage\r\nreturns\rand\nlinefeeds")
        );
    }

    #[test]
    fn it_should_pass_validation() {
        let validation_result = NormalizedString("no_whitespace".to_string())
            .validate_with_context(ValidationContext::default())
            .expect("Error while validating");

        assert_eq!(validation_result, ValidationResult::Passed);
    }

    #[test]
    fn it_should_fail_validation() {
        let validation_result = NormalizedString("spaces and\ttabs".to_string())
            .validate_with_context(ValidationContext::default())
            .expect("Error while validating");

        assert_eq!(
            validation_result,
            ValidationResult::Failed {
                reasons: vec![FailureReason {
                    message: "NormalizedString contains invalid characters \\r \\n \\t or \\r\\n"
                        .to_string(),
                    context: ValidationContext::default()
                }]
            }
        );
    }
}
