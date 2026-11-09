# frozen_string_literal: true

module PiiRedactable
  extend ActiveSupport::Concern

  included do
    # before_save copies content into processed_message_content before before_create
    # runs, so the redaction also rewrites processed_message_content.
    before_create :redact_pii
    before_update :redact_pii, if: :content_changed?
  end

  private

  def redact_pii
    return if content.blank?

    result = PiiRedactor.redact(content)
    self.content = result.text
    self.processed_message_content = content.to_s.truncate(150_000)
    current = additional_attributes.is_a?(Hash) ? additional_attributes.deep_stringify_keys : {}
    current['redaction'] = {
      'entities' => result.entities,
      'engine_version' => result.engine_version
    }
    self.additional_attributes = current
  end
end
